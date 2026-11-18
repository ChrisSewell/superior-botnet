#!/usr/bin/env python3
"""Passive decoder for the "superior" bot's C2 stream (TCP 29444 / 14444) and mesh links (TCP 443).

Offline analysis of captured traffic only. It has no network code and cannot
talk to a bot or a C2.

Input: the two directions of one TCP connection as raw byte files, e.g.
    tshark -r cap.pcap -q -z follow,tcp,raw,<stream>   (then split by direction)

    superior_c2_decode.py --bot2c2 up.bin --c22bot down.bin
    superior_c2_decode.py --c22bot down.bin --session-key <64 hex>
    superior_c2_decode.py --mesh-init a.bin --mesh-listen b.bin     (mesh link, both optional)

What can be read without any secret:
  * the registration frame (static key shipped in every sample)
  * every control message from the C2 (they are plaintext + 8-byte MAC)
Attack commands are ChaCha20 under a per-connection session key. Supply it with
--session-key (read from a lab detonation's memory) or --eph-priv (the bot's
ephemeral X25519 private key); without it they are reported as opaque.

Mesh links (hello "SWR1", then frames) use keys derived from the same static key, so
they decode fully. The mesh part is checked against traffic recorded in an isolated lab;
the C2 part is from code only.

Derived from static analysis of the debug build
sha256 5f7494996239fa4768a89f61b6d3cf710b75fb458c099b6c71d7fb7174c09220.
"""
import argparse
import hashlib
import json
import struct
import sys

STATIC_KEY = bytes.fromhex(
    "a37f2ce158d40b9641f76e1ac93d82550eb74ad36f2891e57c04ba531f86c24d")
CNC_STATIC_PUB = bytes.fromhex(
    "97b9f19a0772d650c3d7db82633793020f2ef78f2f5797a4c64885fd16ce391c")
FIELD_NONCE = bytes.fromhex("7a00c3000000000000000000")
NONCE_BOT2C2 = bytes.fromhex("d15e01000000000000000000")
NONCE_C22BOT = bytes.fromhex("d15e02000000000000000000")
REG_MAGIC = bytes.fromhex("0000000d")
MAX_ATTACK_LEN = 0x1FF8

# Vector id -> handler name in the debug build (names only).
VECTORS = {
    0x00: "udpplain", 0x02: "tcpbypass", 0x04: "ack", 0x07: "sockethold",
    0x0B: "stomp", 0x0E: "udpbypass", 0x11: "http", 0x12: "http_bypass",
    0x14: "cdn_bypass", 0x16: "http3", 0x1F: "h2_down", 0x21: "captcha_bypass",
    0x23: "icmp", 0x24: "ssh", 0x26: "udpstrike", 0x27: "minecraft",
    0x29: "game", 0x2A: "discord", 0x2B: "httpfull", 0x2C: "tcpapp",
    0x2D: "fivem", 0x2E: "cfbypass", 0x2F: "tcpkill", 0x30: "tls_full",
    0x31: "ovh_kill", 0x33: "bricker", 0x34: "boxpersist", 0x35: "kimwolf",
    0x36: "ws", 0x37: "dnsamp", 0x38: "ssdpamp", 0x39: "h2_cont",
    0x3A: "udpxor", 0x3B: "tcprst", 0x3C: "tcpsynack", 0x3D: "dnsq",
    0x3E: "gameudp", 0x3F: "emulate", 0x40: "odom",
}


# ---- primitives -----------------------------------------------------------

def _rotl(v, n):
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 7)


def chacha20_xor(key, counter, nonce, data):
    """IETF ChaCha20 (32-bit block counter, 96-bit nonce)."""
    out = bytearray()
    base = list(struct.unpack("<4I", b"expand 32-byte k")) + \
        list(struct.unpack("<8I", key)) + [0] + list(struct.unpack("<3I", nonce))
    for off in range(0, len(data), 64):
        st = base[:]
        st[12] = (counter + off // 64) & 0xFFFFFFFF
        w = st[:]
        for _ in range(10):
            _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13)
            _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
            _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12)
            _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
        ks = struct.pack("<16I", *[(w[i] + st[i]) & 0xFFFFFFFF for i in range(16)])
        out += bytes(a ^ b for a, b in zip(data[off:off + 64], ks))
    return bytes(out)


def x25519(k, u):
    """RFC 7748 X25519, used only to turn a recovered ephemeral key into the session key."""
    p = 2 ** 255 - 19
    k = bytearray(k); k[0] &= 248; k[31] &= 127; k[31] |= 64
    k = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        if swap ^ kt:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a, b = (x2 + z2) % p, (x2 - z2) % p
        aa, bb = a * a % p, b * b % p
        e = (aa - bb) % p
        c, d = (x3 + z3) % p, (x3 - z3) % p
        da, cb = d * a % p, c * b % p
        x3 = (da + cb) ** 2 % p
        z3 = x1 * (da - cb) ** 2 % p
        x2 = aa * bb % p
        z2 = e * (aa + 121665 * e) % p
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


def derive_session_key(eph_priv, eph_pub):
    shared = x25519(eph_priv, CNC_STATIC_PUB)
    return hashlib.blake2s(shared + eph_pub + CNC_STATIC_PUB).digest()


def derive_mac_key(session_key):
    return hashlib.blake2s(b"mac", key=session_key).digest()


def tag8(mac_key, data):
    return hashlib.blake2s(data, key=mac_key).digest()[:8]


# ---- bot -> C2 ------------------------------------------------------------

def _text(b):
    return b.decode("utf-8", "replace")


def parse_registration(pt):
    if pt[:4] != REG_MAGIC:
        raise ValueError("registration magic mismatch: %s" % pt[:4].hex())
    pos = 4

    def lv():
        nonlocal pos
        n = pt[pos]
        v = pt[pos + 1:pos + 1 + n]
        if len(v) != n:
            raise ValueError("truncated field")
        pos += 1 + n
        return v

    arch, version = lv(), lv()
    cores = chacha20_xor(STATIC_KEY, 1, FIELD_NONCE, lv())
    ram = chacha20_xor(STATIC_KEY, 2, FIELD_NONCE, lv())
    ident = chacha20_xor(STATIC_KEY, 3, FIELD_NONCE, lv())
    root = pt[pos]; pos += 1
    cmdline, cpu = lv(), lv()
    tail = pt[pos:]
    if len(tail) != 40:
        raise ValueError("expected 40 trailing bytes, got %d" % len(tail))
    return {
        "type": "registration", "arch": _text(arch), "version": _text(version),
        "cores": _text(cores), "ram": _text(ram), "identifier": _text(ident),
        "root_flag": root, "cmdline": _text(cmdline), "cpu_model": _text(cpu),
        "eph_pub": tail[:32].hex(), "bot_id": tail[32:].hex(),
    }


def decode_bot2c2(buf):
    """Yield decoded messages from the bot->C2 byte stream."""
    if len(buf) < 2:
        return
    n = struct.unpack(">H", buf[:2])[0]
    body = buf[2:2 + n]
    if len(body) < n:
        yield {"type": "truncated", "dir": "bot>c2", "need": n, "have": len(body)}
        return
    try:
        # counter 0: c2_send_ctr is reset on every connect
        msg = parse_registration(chacha20_xor(STATIC_KEY, 0, NONCE_BOT2C2, body))
    except (ValueError, IndexError) as e:
        yield {"type": "error", "dir": "bot>c2", "error": str(e)}
        return
    msg["dir"] = "bot>c2"
    yield msg
    pos, keepalives = 2 + n, 0
    while pos + 2 <= len(buf):
        h = buf[pos:pos + 2]
        if h == b"\x00\x00":
            keepalives += 1
            pos += 2
        elif h == b"\xff\xf9" and pos + 10 <= len(buf):
            yield {"type": "gate_echo", "dir": "bot>c2",
                   "challenge": buf[pos + 2:pos + 10].hex()}
            pos += 10
        else:
            yield {"type": "unknown", "dir": "bot>c2", "offset": pos,
                   "bytes": buf[pos:pos + 32].hex()}
            break
    if keepalives:
        yield {"type": "keepalive", "dir": "bot>c2", "count": keepalives}


# ---- C2 -> bot ------------------------------------------------------------

def parse_attack(pt):
    vec, dur, nt = pt[0], struct.unpack(">H", pt[1:3])[0], pt[3]
    if not 1 <= nt <= 32:
        raise ValueError("target count %d out of range" % nt)
    pos, targets = 4, []
    for _ in range(nt):
        ip, mask = pt[pos:pos + 4], pt[pos + 4]
        targets.append("%d.%d.%d.%d/%d" % (*ip, mask))
        pos += 5
    opts = []
    if pos < len(pt):
        no = pt[pos]; pos += 1
        for _ in range(no):
            k, ln = pt[pos], pt[pos + 1]
            v = pt[pos + 2:pos + 2 + ln]
            if len(v) != ln:
                raise ValueError("truncated option")
            opts.append({"key": k, "value": _text(v)})
            pos += 2 + ln
    return {"vector": vec, "vector_name": VECTORS.get(vec, "unknown"),
            "duration_s": dur or 60, "targets": targets, "options": opts}


class Need(Exception):
    pass


def decode_c22bot(buf, session_key=None):
    """Yield decoded messages from the C2->bot byte stream."""
    mac_key = derive_mac_key(session_key) if session_key else None
    pos, recv_ctr, start = 0, 0, 0

    def take(n):
        nonlocal pos
        if pos + n > len(buf):
            raise Need()
        v = buf[pos:pos + n]
        pos += n
        return v

    def mac(msg, signed, tag):
        msg["dir"] = "c2>bot"
        msg["tag"] = tag.hex()
        if mac_key:
            msg["tag_ok"] = tag8(mac_key, signed) == tag
        return msg

    try:
        while pos < len(buf):
            start = pos
            hdr = take(2)
            h = struct.unpack(">H", hdr)[0]
            if h == 0x0000:
                yield mac({"type": "stop_all"}, hdr, take(8))
            elif h == 0xFFFF:
                yield mac({"type": "self_destruct"}, hdr, take(8))
            elif h == 0xFFFE:
                ln = take(2); url = take(struct.unpack(">H", ln)[0])
                flag = take(1); digest = take(32) if flag[0] else b""
                yield mac({"type": "update", "url": _text(url),
                           "blake2s": digest.hex() or None},
                          hdr + ln + url + flag + digest, take(8))
            elif h == 0xFFFD:
                ln = take(2); path = take(struct.unpack(">H", ln)[0])
                yield mac({"type": "filepull", "path": _text(path)},
                          hdr + ln + path, take(8))
            elif h == 0xFFFC:
                f = take(1)
                yield mac({"type": "killer_config", "enabled": f[0] & 1,
                           "aggression": (f[0] >> 1) & 3, "pull": (f[0] >> 3) & 1,
                           "swarm": (f[0] >> 4) & 1}, hdr + f, take(8))
            elif h == 0xFFFB:
                n = take(1); peers = take(4 * min(n[0], 16))
                yield mac({"type": "mesh_peers", "peers": [
                    "%d.%d.%d.%d" % tuple(peers[i:i + 4])
                    for i in range(0, len(peers), 4)]}, hdr + n + peers, take(8))
            elif h == 0xFFFA:
                tag = take(8); arg = take(8); rounds = take(1)
                yield mac({"type": "benchmark", "arg": arg.hex(),
                           "rounds": rounds[0]}, hdr, tag)
            elif h == 0xFFF9:
                # 8 bytes: either a MAC over the header (self-report request) or a
                # challenge followed by its MAC. Only the MAC key tells them apart.
                first = take(8)
                if mac_key and tag8(mac_key, hdr) == first:
                    yield mac({"type": "self_report_request"}, hdr, first)
                elif mac_key:
                    yield mac({"type": "gate_challenge", "challenge": first.hex()},
                              hdr + first, take(8))
                else:
                    yield {"type": "gate_or_self_report", "dir": "c2>bot",
                           "first8": first.hex(),
                           "note": "ambiguous without the session key; stopping"}
                    return
            elif h <= MAX_ATTACK_LEN:
                ct = take(h); tag = take(8)
                msg = {"type": "attack", "length": h, "counter": recv_ctr}
                if session_key:
                    try:
                        msg.update(parse_attack(chacha20_xor(
                            session_key, recv_ctr, NONCE_C22BOT, ct)))
                    except (ValueError, IndexError, struct.error) as e:
                        msg["error"] = str(e)
                else:
                    msg["ciphertext"] = ct.hex()
                recv_ctr += 1
                yield mac(msg, hdr + ct, tag)
            else:
                yield {"type": "unknown", "dir": "c2>bot", "offset": start,
                       "header": hdr.hex()}
                return
    except Need:
        yield {"type": "truncated", "dir": "c2>bot", "offset": start}


# ---- mesh (TCP 443) --------------------------------------------------------

MESH_MAC_KEY = hashlib.blake2s(b"swarm-mac-v1", key=STATIC_KEY).digest()
NONCE_MESH_INIT = bytes.fromhex("535741010000000000000000")    # dialling side
NONCE_MESH_LISTEN = bytes.fromhex("535742020000000000000000")  # accepting side
MESH_TYPES = {1: "peer_exchange", 2: "attack", 3: "stop", 4: "kill", 5: "ping", 6: "pong",
              7: "scare", 8: "killer_config", 9: "log_request", 10: "log_line",
              11: "locker", 12: "blocklist", 13: "op", 14: "op_output", 15: "op_targeted",
              16: "sys_facts"}


def mesh_mac(data):
    return hashlib.blake2s(data, key=MESH_MAC_KEY, digest_size=16).digest()


def decode_mesh(buf, initiator):
    """Yield the hello and frames of one direction of a mesh link."""
    side = "init" if initiator else "listen"
    if len(buf) < 35 or buf[:4] != b"SWR1":
        yield {"type": "not_mesh", "dir": side}
        return
    h = buf[:35]
    yield {"type": "hello", "dir": side, "version": h[4], "node_id": h[5:13].hex(),
           "listen_port": struct.unpack(">H", h[13:15])[0],
           "peer_addr": "%d.%d.%d.%d" % tuple(h[15:19]), "mac_ok": mesh_mac(h[:19]) == h[19:]}
    nonce = NONCE_MESH_INIT if initiator else NONCE_MESH_LISTEN
    pos, ctr = 35, 0
    while pos + 2 <= len(buf):
        ln = struct.unpack(">H", buf[pos:pos + 2])[0]
        ct, tag = buf[pos + 2:pos + 2 + ln], buf[pos + 2 + ln:pos + 18 + ln]
        if len(tag) < 16 or ln < 12:
            yield {"type": "truncated", "dir": side, "offset": pos}
            return
        pt = chacha20_xor(STATIC_KEY, ctr, nonce, ct)
        plen = struct.unpack(">H", pt[10:12])[0]
        msg = {"type": MESH_TYPES.get(pt[0], "type_%d" % pt[0]), "dir": side, "counter": ctr,
               "flag": pt[1], "msg_id": pt[2:10].hex(), "payload": pt[12:12 + plen].hex(),
               "mac_ok": mesh_mac(ct) == tag}
        if pt[0] == 2:
            try:
                msg.update(parse_attack(pt[12:12 + plen]))
            except (ValueError, IndexError, struct.error) as e:
                msg["error"] = str(e)
        yield msg
        pos += 18 + ln
        ctr += 1


# ---- self-test (synthetic data only) --------------------------------------

def _selftest():
    # RFC 8439 2.4.2 ChaCha20 vector and RFC 7748 5.2 X25519 vector
    k = bytes(range(32)); n = bytes.fromhex("000000000000004a00000000")
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
          b"only one tip for the future, sunscreen would be it.")
    assert chacha20_xor(k, 1, n, pt)[:16].hex() == "6e2e359a2568f98041ba0728dd0d6981"
    assert x25519(
        bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
        bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    ).hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"

    def lv(b):
        return bytes([len(b)]) + b

    eph_pub = bytes(range(32, 64))
    reg = (REG_MAGIC + lv(b"armv7l") + lv(b"superior-v21")
           + lv(chacha20_xor(STATIC_KEY, 1, FIELD_NONCE, b"4"))
           + lv(chacha20_xor(STATIC_KEY, 2, FIELD_NONCE, b"1024"))
           + lv(chacha20_xor(STATIC_KEY, 3, FIELD_NONCE, b"test.telnet"))
           + b"\x01" + lv(b"/bin/busybox sh") + lv(b"Test CPU")
           + eph_pub + bytes(8))
    up = struct.pack(">H", len(reg)) + chacha20_xor(STATIC_KEY, 0, NONCE_BOT2C2, reg)
    up += b"\x00\x00" * 3
    out = list(decode_bot2c2(up))
    assert out[0]["arch"] == "armv7l" and out[0]["ram"] == "1024", out
    assert out[0]["identifier"] == "test.telnet" and out[1]["count"] == 3, out

    sk = hashlib.blake2s(b"selftest").digest(); mk = derive_mac_key(sk)
    atk = bytes([0x11]) + struct.pack(">H", 30) + b"\x01" + bytes([192, 0, 2, 1, 32]) \
        + b"\x01" + bytes([7, 2]) + b"80"
    ct = chacha20_xor(sk, 0, NONCE_C22BOT, atk)
    h = struct.pack(">H", len(ct))
    down = b"\xff\xfc\x13" + tag8(mk, b"\xff\xfc\x13")
    down += h + ct + tag8(mk, h + ct)
    down += b"\x00\x00" + tag8(mk, b"\x00\x00")
    out = list(decode_c22bot(down, sk))
    assert [m["type"] for m in out] == ["killer_config", "attack", "stop_all"], out
    assert all(m["tag_ok"] for m in out), out
    assert out[1]["targets"] == ["192.0.2.1/32"] and out[1]["vector_name"] == "http"
    assert [m["type"] for m in decode_c22bot(down)] == \
        ["killer_config", "attack", "stop_all"]
    hello = b"SWR1\x01" + bytes(8) + struct.pack(">H", 443) + bytes(4)
    inner = bytes([5, 1]) + bytes(8) + struct.pack(">H", 4) + b"abcd"
    ct = chacha20_xor(STATIC_KEY, 0, NONCE_MESH_INIT, inner)
    link = hello + mesh_mac(hello) + struct.pack(">H", len(ct)) + ct + mesh_mac(ct)
    out = list(decode_mesh(link, True))
    assert [m["type"] for m in out] == ["hello", "ping"] and all(m["mac_ok"] for m in out), out
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("--bot2c2", help="raw bytes, bot to C2 direction")
    ap.add_argument("--c22bot", help="raw bytes, C2 to bot direction")
    ap.add_argument("--mesh-init", help="raw bytes, dialling side of a mesh link")
    ap.add_argument("--mesh-listen", help="raw bytes, accepting side of a mesh link")
    ap.add_argument("--session-key", help="64 hex chars")
    ap.add_argument("--eph-priv", help="bot ephemeral X25519 private key, 64 hex chars")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return _selftest()
    for path, init in ((a.mesh_init, True), (a.mesh_listen, False)):
        if path:
            for m in decode_mesh(open(path, "rb").read(), init):
                print(json.dumps(m))
    if a.mesh_init or a.mesh_listen:
        return
    if not (a.bot2c2 or a.c22bot):
        ap.error("give --bot2c2 and/or --c22bot")
    sk = bytes.fromhex(a.session_key) if a.session_key else None
    if a.bot2c2:
        for m in decode_bot2c2(open(a.bot2c2, "rb").read()):
            if m.get("type") == "registration" and a.eph_priv and not sk:
                sk = derive_session_key(bytes.fromhex(a.eph_priv),
                                        bytes.fromhex(m["eph_pub"]))
            print(json.dumps(m))
    if a.c22bot:
        for m in decode_c22bot(open(a.c22bot, "rb").read(), sk):
            print(json.dumps(m))


if __name__ == "__main__":
    sys.exit(main())
