#!/usr/bin/env python3
"""
redtail.py - experimental authenticated file transport over TCP.

How it works (no new protocol - just bytes on TCP):
  1. Each TCP stream does its own ephemeral ECDH handshake (X25519 or P-256).
  2. HKDF-SHA256(shared_secret, salt=session_id, info=stream_idx) -> 256-bit stream key.
  3. The file is cut into N contiguous stripes, one per stream. Each stripe is shipped
     as AEAD-sealed records (AES-256-GCM or ChaCha20-Poly1305):

        | sequence u64 | length u32 | ciphertext (length bytes) | tag 16B |
        |<-- 12B header = AAD -->|

     nonce = stream_idx (4B) || record_counter (8B)  -> never reused under one key.
  4. Every stream carries an authenticated byte-count control. Optional HUNTSPF
     modes add GF(256) field arms; RS42 adds systematic Reed-Solomon 4+2 shards.
     Records use ordinal sequence numbers rather than file coordinates. The receiver
     authenticates each stream and concatenates completed parts by stream index.
     No filename or whole-file SHA-256 is sent.

Modes:
  pdu    print per-packet (PDU) math
  bench  receiver + sender on loopback (127.0.0.1 -> 127.0.0.2), sweep settings
  recv   listen and rebuild files                (real two-host use)
  send   send files or folders (-r) to a host (--to) or a local disk (--drop)
  unpack-blob  safely extract an XBL1 container
"""
import argparse, csv, hashlib, hmac, multiprocessing as mp, os, queue, shutil, socket, struct, sys, tempfile, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"XMT4"
HELLO = struct.Struct("!4s16sHHBB")   # magic, session id, stream idx, n streams, curve, cipher
REC = struct.Struct("!QI")            # sequence, plaintext length (authenticated as AAD)
SUMMARY = struct.Struct("!Q")         # byte count for this stream
SPF = struct.Struct("!BQ")            # formal C0 control id, byte count
TAG = 16
SUMMARY_RECORD = 0xFFFFFFFFFFFFFFFF
CHECKPOINT_RECORD = SUMMARY_RECORD - 1
SPF_RECORD = CHECKPOINT_RECORD - 1
SPF2_RECORD = SPF_RECORD - 1
SPF3_RECORD = SPF2_RECORD - 1
SPF4_RECORD = SPF3_RECORD - 1
RS42_RECORD = SPF4_RECORD - 1
SPF_RS42_RECORD = RS42_RECORD - 1
SPF_C0 = 0
RS42 = struct.Struct("!BQ")            # six-bit shard mask, original stream length
CURVES = ["x25519", "p256"]
CIPHERS = ["aes256gcm", "chacha20", "stream"]   # stream = AES-CTR + HMAC checkpoints
PUBLEN = {"x25519": 32, "p256": 33}
CTX = mp.get_context("fork")
BLOB_MAGIC = b"XBL1"
BLOB_HEAD = struct.Struct("!4sI")       # magic, file count
BLOB_ENTRY = struct.Struct("!HQ")      # UTF-8 basename length, file size
QUICK_START = ("python3 redtail.py send file-1.bin file-2.bin file-3.bin "
               "--to 10.0.0.1:47000 --blob --mode record --HUNTSPF3 "
               "--RS42 --drop-shards 0 2")
SEND_EXAMPLES = """Examples:
  # network: one session per file, or one --blob session
  python3 redtail.py send a.bin b.bin --to 10.0.0.1:47000
  python3 redtail.py send -r ./dir --to 10.0.0.1:47000 --blob

  # local file drop onto a disk, verified by SHA-256 (no receiver needed)
  python3 redtail.py send -r ./dir --drop /Volumes/SSD/test
  python3 redtail.py send -r ./dir --drop /Volumes/SSD/test --RS42 --drop-shards 2 3

  # pack a whole drive into one container on itself, following symlinks
  python3 redtail.py send -r -L "/Volumes/SSD" --drop "/Volumes/SSD/redtail-test" \\
    --blob --RS42 --drop-shards 2 3 --mode record
  python3 redtail.py unpack-blob "/Volumes/SSD/redtail-test/"redtail-blob-*.xbl1 --out ~/restore

  # put the --blob temporary container on another disk
  TMPDIR=/Volumes/Other python3 redtail.py send -r ./dir --drop /Volumes/SSD/test --blob

  # full lab mode: SPF3 arms inside RS42 with two lost shards
  """ + QUICK_START + """

Notes:
  folders need -r; symlinks are skipped unless -L; macOS volume folders
  (.Spotlight-V100, .fseventsd, .Trashes, ...) and the --drop folder are left out
  --drop checks free space first: about total + largest file on the target disk,
  plus total in TMPDIR when --blob is used; existing files are never replaced
  --HUNTSPF/--HUNTSPF2 do not combine with --RS42; use --HUNTSPF3/4
  XMT4 never compresses: output size equals input size"""


# ---------------------------------------------------------------- crypto helpers
def gen_key(curve):
    if curve == "x25519":
        k = x25519.X25519PrivateKey.generate()
        return k, k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    k = ec.generate_private_key(ec.SECP256R1())
    return k, k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def ecdh(curve, priv, peer):
    if curve == "x25519":
        return priv.exchange(x25519.X25519PublicKey.from_public_bytes(peer))
    return priv.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer))


def derive(secret, session, idx, label=b""):
    return HKDF(hashes.SHA256(), 32, salt=session,
                info=b"matter-transport/v1/" + label + struct.pack("!H", idx)).derive(secret)


# --- stream mode: 1 byte in = 1 byte on the wire, plus one 16B HMAC tag per checkpoint
def stream_keys(secret, session, idx):
    return derive(secret, session, idx, b"ctr/"), derive(secret, session, idx, b"mac/")


def aes_ctr(key):
    return Cipher(algorithms.AES(key), modes.CTR(bytes(16)))   # key is unique per session+stream


def ckpt_mac(kmac, n):
    return hmac.new(kmac, struct.pack("!Q", n), hashlib.sha256)


def make_aead(cipher, key):
    return {"aes256gcm": AESGCM, "chacha20": ChaCha20Poly1305, "stream": AESGCM}[cipher](key)


def nonce(idx, ctr):
    return struct.pack("!IQ", idx, ctr)


GF256_MUL2 = bytes((((b << 1) & 0xff) ^ (0x1d if b & 0x80 else 0)) for b in range(256))

GF_EXP = [0] * 512
GF_LOG = [0] * 256
_x = 1
for _i in range(255):
    GF_EXP[_i] = _x
    GF_LOG[_x] = _i
    _x = ((_x << 1) & 0xff) ^ (0x1d if _x & 0x80 else 0)
for _i in range(255, 512):
    GF_EXP[_i] = GF_EXP[_i - 255]
GF_MUL_TABLE = tuple(bytes(0 if a == 0 or b == 0 else GF_EXP[GF_LOG[a] + GF_LOG[b]]
                           for b in range(256)) for a in range(256))
RS42_ROWS = ((1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1),
             (1, 1, 1, 1), (1, 2, 4, 8))


def gf256_mul2_vector(data):
    """Multiply each byte by x in GF(256), field polynomial 0x11d."""
    return data.translate(GF256_MUL2)


def spf_arms(data, level):
    arms = [bytes(data)]
    for _ in range(1, level):
        arms.append(gf256_mul2_vector(arms[-1]))
    return arms


def pack_spf_control(length, level):
    return b"".join(bytes((i,)) + arm for i, arm in
                    enumerate(spf_arms(length.to_bytes(8, "big"), level)))


def gf_mul(a, b):
    return GF_MUL_TABLE[a][b]


def gf_matrix_inverse(matrix):
    n = len(matrix)
    work = [list(row) + [1 if r == c else 0 for c in range(n)]
            for r, row in enumerate(matrix)]
    for col in range(n):
        pivot = next((r for r in range(col, n) if work[r][col]), None)
        if pivot is None:
            raise ValueError("singular GF(256) shard matrix")
        work[col], work[pivot] = work[pivot], work[col]
        inv = GF_EXP[255 - GF_LOG[work[col][col]]]
        work[col] = [gf_mul(v, inv) for v in work[col]]
        for r in range(n):
            if r != col and work[r][col]:
                factor = work[r][col]
                work[r] = [a ^ gf_mul(factor, b) for a, b in zip(work[r], work[col])]
    return tuple(tuple(row[n:]) for row in work)


def gf_linear_combine(shards, coefficients):
    terms = []
    for shard, coefficient in zip(shards, coefficients):
        if coefficient:
            terms.append(shard if coefficient == 1 else shard.translate(GF_MUL_TABLE[coefficient]))
    if not terms:
        return bytes(len(shards[0]))
    if len(terms) == 1:
        return bytes(terms[0])
    value = 0
    for term in terms:
        value ^= int.from_bytes(term, "big")
    return value.to_bytes(len(terms[0]), "big")


def rs42_encode(data):
    shard_size = -(-len(data) // 4)
    padded = data + bytes(4 * shard_size - len(data))
    shards = [padded[i * shard_size:(i + 1) * shard_size] for i in range(4)]
    shards.extend(gf_linear_combine(shards, row) for row in RS42_ROWS[4:])
    return shards


def rs42_decoder(indices):
    if len(indices) < 4:
        raise ValueError("RS(4+2) requires at least four received shards")
    chosen = tuple(indices[:4])
    return chosen, gf_matrix_inverse(tuple(RS42_ROWS[i] for i in chosen))


def recv_exact(sock, n):
    buf = bytearray(n); mv = memoryview(buf); got = 0
    while got < n:
        r = sock.recv_into(mv[got:], n - got)
        if r == 0:
            raise ConnectionError("peer closed mid-record")
        got += r
    return buf


def parse_target(target, default_port):
    """Accept 'host', 'host:port', '[v6]:port'. Resolve once, in the parent, before forking."""
    host, port = target, default_port
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") else default_port
    elif target.count(":") == 1:
        host, p = target.split(":")
        port = int(p)
    if host in ("", "0.0.0.0", "::"):
        print(f"note: {host or 'empty'} is a listen-on-everything address, not a destination; "
              f"sending to 127.0.0.1 instead", file=sys.stderr)
        host = "127.0.0.1"
    fam, _, _, _, sa = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)[0]
    return sa[0], port


# ---------------------------------------------------------------- MTU / MSS awareness
TS_OPT = 12                                       # TCP timestamp option (on by default on Linux/macOS)


def mss_for_mtu(mtu, v6=False, ts=True):
    return mtu - (40 if v6 else 20) - 20 - (TS_OPT if ts else 0)


def live_mss(sock):
    """Negotiated MSS for this connection: min of both ends' MTU and any path-MTU clamp."""
    try:
        return sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
    except OSError:
        return None


def fit_record(target, mss, overhead):
    """Fit one application record inside one negotiated TCP segment."""
    mss = mss or 1448
    return max(1, min(target, mss - overhead))


# ---------------------------------------------------------------- receiver
def serve_one(conn, outdir):
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    magic, session, idx, n, c, k = HELLO.unpack(recv_exact(conn, HELLO.size))
    if magic != MAGIC:
        raise ValueError("bad magic")
    curve, cipher = CURVES[c], CIPHERS[k]
    peer = bytes(recv_exact(conn, PUBLEN[curve]))
    priv, pub = gen_key(curve)
    conn.sendall(pub)
    secret = ecdh(curve, priv, peer)
    aead = make_aead(cipher, derive(secret, session, idx))
    if cipher == "stream":
        return serve_stream(conn, aead, secret, session, idx, n, outdir)
    over = TAG if aead else 0
    ctr, fd, nbytes, summary, expected_seq = 0, None, 0, None, 0
    while True:
        hdr = recv_exact(conn, REC.size)
        seq, ln = REC.unpack(hdr)
        body = recv_exact(conn, ln + over)
        pt = aead.decrypt(nonce(idx, ctr), body, bytes(hdr)) if aead else body  # raises on tamper
        ctr += 1
        if seq in (SUMMARY_RECORD, SPF_RECORD, SPF2_RECORD, SPF3_RECORD, SPF4_RECORD,
                   RS42_RECORD, SPF_RS42_RECORD):
            if summary is not None:
                raise ValueError("duplicate stream summary")
            if seq == SPF_RS42_RECORD:
                fd, summary = open_spf_rs42_summary(pt, session, idx, outdir)
            elif seq == RS42_RECORD:
                fd, summary = open_rs42_summary(pt, session, idx, outdir)
            else:
                level = {SUMMARY_RECORD: 0, SPF_RECORD: 1, SPF2_RECORD: 2,
                         SPF3_RECORD: 3, SPF4_RECORD: 4}[seq]
                fd, summary = open_summary(pt, session, idx, outdir, spf_level=level)
        elif ln == 0:
            if summary is None or seq != expected_seq or nbytes != summary["length"]:
                raise ValueError("stream ended before its authenticated summary was satisfied")
            break                                  # authenticated end-of-stripe
        else:
            if summary is None:
                raise ValueError("data arrived before its stream summary")
            level = summary["spf_level"]
            decoded = pt
            if summary.get("rs42"):
                indices = summary["shard_indices"]
                if len(pt) % len(indices):
                    raise ValueError("RS(4+2) record has unequal shard sizes")
                shard_size = len(pt) // len(indices)
                received = [bytes(pt[i * shard_size:(i + 1) * shard_size])
                            for i in range(len(indices))]
                chosen, inverse = summary["decoder"]
                selected = [received[indices.index(i)] for i in chosen]
                data_shards = [gf_linear_combine(selected, row) for row in inverse]
                decoded = b"".join(data_shards)
            remaining = summary["length"] - nbytes
            if level >= 3:
                if summary.get("rs42"):
                    candidate = len(decoded) // level
                    arm_len = candidate if len(decoded) % level == 0 and candidate <= remaining else remaining
                    decoded = decoded[:arm_len * level]
                if len(decoded) % level:
                    raise ValueError("compound SPF record has unequal arm sizes")
                arm_len = len(decoded) // level
                arms = [bytes(decoded[i * arm_len:(i + 1) * arm_len]) for i in range(level)]
                expected = spf_arms(arms[0], level)
                if any(not hmac.compare_digest(a, b) for a, b in zip(arms[1:], expected[1:])):
                    raise ValueError(f"HUNTSPF{level} payload field relation failed")
                plain = arms[0]
            else:
                plain = decoded[:remaining]
            if seq != expected_seq or nbytes + len(plain) > summary["length"]:
                raise ValueError("record sequence or summarized byte count is invalid")
            os.write(fd, plain); nbytes += len(plain); expected_seq += 1
    os.close(fd)
    conn.sendall(b"OK")
    conn.close()
    return {"session": session, "idx": idx, "n": n, "nbytes": nbytes,
            "summary": summary}


def session_path(session, outdir):
    """Use the random session identifier as the untrusted peer's only output name."""
    return os.path.join(outdir, f"{session.hex()}.bin")


def part_path(session, idx, outdir):
    return os.path.join(outdir, f".{session.hex()}.{idx}.part")


def open_summary(pt, session, idx, outdir, spf_level=0):
    """Open an isolated part using its authenticated summarized byte count."""
    if spf_level >= 2:
        if len(pt) != 9 * spf_level:
            raise ValueError(f"invalid formal SPF{spf_level} control size")
        vectors = []
        for i in range(spf_level):
            if pt[9 * i] != i:
                raise ValueError(f"HUNTSPF{spf_level} control arms are not ordered")
            vectors.append(bytes(pt[9 * i + 1:9 * (i + 1)]))
        expected = spf_arms(vectors[0], spf_level)
        if any(not hmac.compare_digest(a, b) for a, b in zip(vectors[1:], expected[1:])):
            raise ValueError(f"HUNTSPF{spf_level} control field relation failed")
        length = int.from_bytes(vectors[0], "big")
        control = "+".join(f"C{i}" for i in range(spf_level))
    elif spf_level == 1:
        if len(pt) != SPF.size:
            raise ValueError("invalid formal SPF control size")
        control, length = SPF.unpack(pt)
        if control != SPF_C0:
            raise ValueError("XMT4 HUNTSPF accepts only the C0 control")
        control = "C0"
    else:
        if len(pt) != SUMMARY.size:
            raise ValueError("stream must carry exactly one byte-count summary")
        length, = SUMMARY.unpack(pt)
        control = None
    path = part_path(session, idx, outdir)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    return fd, {"length": length, "path": path, "spf_level": spf_level, "control": control}


def open_rs42_summary(pt, session, idx, outdir):
    if len(pt) != RS42.size:
        raise ValueError("invalid RS(4+2) control size")
    mask, length = RS42.unpack(pt)
    if mask & ~0x3f:
        raise ValueError("RS(4+2) shard mask has unknown bits")
    indices = tuple(i for i in range(6) if mask & (1 << i))
    decoder = rs42_decoder(indices)
    path = part_path(session, idx, outdir)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    return fd, {"length": length, "path": path, "spf_level": 0, "control": None,
                "rs42": True, "shard_mask": mask, "shard_indices": indices,
                "decoder": decoder}


def open_spf_rs42_summary(pt, session, idx, outdir):
    if len(pt) < 2:
        raise ValueError("invalid combined SPF+RS(4+2) control")
    level, mask = pt[0], pt[1]
    if level not in (3, 4):
        raise ValueError("combined RS(4+2) supports HUNTSPF3 or HUNTSPF4")
    fd, summary = open_summary(pt[2:], session, idx, outdir, spf_level=level)
    if mask & ~0x3f:
        os.close(fd)
        raise ValueError("RS(4+2) shard mask has unknown bits")
    indices = tuple(i for i in range(6) if mask & (1 << i))
    summary.update(rs42=True, shard_mask=mask, shard_indices=indices,
                   decoder=rs42_decoder(indices))
    return fd, summary


def read_sealed(conn, aead, idx, ctr):
    hdr = recv_exact(conn, REC.size)
    off, ln = REC.unpack(hdr)
    return off, aead.decrypt(nonce(idx, ctr), recv_exact(conn, ln + TAG), bytes(hdr))


def serve_stream(conn, aead, secret, session, idx, n, outdir):
    """Raw AES-CTR byte stream; every `ckpt` bytes a 16B HMAC tag. Each chunk is verified
    BEFORE it is written, so nothing unauthenticated ever lands on disk."""
    kind, pt = read_sealed(conn, aead, idx, 0)
    if kind not in (SUMMARY_RECORD, SPF_RECORD, SPF2_RECORD, SPF3_RECORD, SPF4_RECORD):
        raise ValueError("missing stream byte-count summary")
    level = {SUMMARY_RECORD: 0, SPF_RECORD: 1, SPF2_RECORD: 2,
             SPF3_RECORD: 3, SPF4_RECORD: 4}[kind]
    fd, summary = open_summary(pt, session, idx, outdir, spf_level=level)
    kind, pt = read_sealed(conn, aead, idx, 1)
    if kind != CHECKPOINT_RECORD or len(pt) != 4:
        raise ValueError("missing stream checkpoint summary")
    ckpt = struct.unpack("!I", pt)[0]
    if ckpt <= 0:
        raise ValueError("checkpoint size must be positive")
    length = summary["length"]
    kctr, kmac = stream_keys(secret, session, idx)
    dec = aes_ctr(kctr).decryptor()
    off, k = 0, 0
    end = length
    while off < end:
        ct = recv_exact(conn, min(ckpt, end - off))
        m = ckpt_mac(kmac, k); m.update(ct)
        if not hmac.compare_digest(m.digest()[:TAG], bytes(recv_exact(conn, TAG))):
            raise ValueError(f"stream {idx}: checkpoint {k} failed authentication")
        os.write(fd, dec.update(bytes(ct)))
        off += len(ct); k += 1
    os.close(fd)
    conn.sendall(b"OK")
    conn.close()
    return {"session": session, "idx": idx, "n": n, "nbytes": length,
            "summary": summary}


def worker_loop(lsock, outdir, q):
    while True:
        conn, _ = lsock.accept()
        try:
            q.put(serve_one(conn, outdir))
        except Exception as e:                     # keep serving; report the failure
            q.put(("ERR", repr(e)))
            conn.close()


class Receiver:
    def __init__(self, host, port, outdir, workers, clamp_mss=None):
        os.makedirs(outdir, exist_ok=True)
        self.lsock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if clamp_mss:                              # simulate a smaller-MTU network (VPN, PPPoE, ...)
            self.lsock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, clamp_mss)
        self.lsock.bind((host, port))
        self.lsock.listen(64)
        self.q = CTX.Queue()
        self.procs = [CTX.Process(target=worker_loop, args=(self.lsock, outdir, self.q), daemon=True)
                      for _ in range(workers)]
        for p in self.procs:
            p.start()

    def collect(self):
        """Block until one full session has arrived; verify and return a report."""
        sessions = {}
        while True:
            item = self.q.get()
            if isinstance(item, tuple) and item[0] == "ERR":  # e.g. MSS probe / dropped client
                print(f"[recv] connection dropped: {item[1]}", file=sys.stderr, flush=True)
                continue
            session, idx, n = item["session"], item["idx"], item["n"]
            if not 1 <= n <= 65535 or not 0 <= idx < n:
                print("[recv] invalid stream index/count", file=sys.stderr, flush=True)
                continue
            s = sessions.setdefault(session, {"n": n, "parts": {}})
            if s["n"] != n or idx in s["parts"]:
                print("[recv] conflicting or duplicate stream", file=sys.stderr, flush=True)
                continue
            s["parts"][idx] = item
            if len(s["parts"]) == n:
                ok, reason = True, "authenticated stream summaries assembled"
                total = 0
                spf_level = s["parts"][0]["summary"]["spf_level"]
                rs42_mode = s["parts"][0]["summary"].get("rs42", False)
                for stream_idx in range(n):
                    part = s["parts"].get(stream_idx)
                    summary = part and part["summary"]
                    if not summary:
                        ok, reason = False, f"missing summary for stream {stream_idx}"
                        break
                    if summary["spf_level"] != spf_level:
                        ok, reason = False, "mixed SPF and ordinary summaries"
                        break
                    if summary.get("rs42", False) != rs42_mode:
                        ok, reason = False, "mixed RS(4+2) and ordinary summaries"
                        break
                    if part["nbytes"] != summary["length"]:
                        ok, reason = False, f"stream {stream_idx} byte count does not match its summary"
                        break
                    total += summary["length"]
                path = session_path(session, os.path.dirname(s["parts"][0]["summary"]["path"]))
                if ok:
                    assembling = path + ".assembling"
                    with open(assembling, "wb") as dst:
                        os.chmod(assembling, 0o600)
                        for stream_idx in range(n):
                            part_file = s["parts"][stream_idx]["summary"]["path"]
                            with open(part_file, "rb") as src:
                                while block := src.read(1 << 20):
                                    dst.write(block)
                            os.remove(part_file)
                    os.replace(assembling, path)
                del sessions[session]
                return {"path": path, "size": total, "ok": ok,
                        "complete": ok, "completion_flag": 1 if ok else 0,
                        "reason": reason,
                        "manifest_records": 0,
                        "coordinate_records": 0,
                        "summary_records": n if spf_level == 0 and not rs42_mode else 0,
                        "spf_records": n if spf_level else 0,
                        "hunt_spf": spf_level == 1,
                        "hunt_spf2": spf_level == 2,
                        "hunt_spf3": spf_level == 3,
                        "hunt_spf4": spf_level == 4,
                        "spf_control": s["parts"][0]["summary"]["control"],
                        "rs42": rs42_mode,
                        "rs42_records": n if rs42_mode else 0,
                        "rs42_received_shards": list(s["parts"][0]["summary"].get("shard_indices", ())) }

    def close(self):
        for p in self.procs:
            p.terminate()
        self.lsock.close()


# ---------------------------------------------------------------- sender
def send_stripe(host, port, src, path, session, idx, n, lo, hi, rec, curve, cipher,
                out, ckpt=65536, huntspf=False, huntspf2=False,
                huntspf3=False, huntspf4=False, rs42=False, shard_mask=0x3f):
    s = socket.create_connection((host, port), source_address=(src, 0) if src else None)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    t0 = time.perf_counter()
    s.sendall(HELLO.pack(MAGIC, session, idx, n, CURVES.index(curve), CIPHERS.index(cipher)))
    priv, pub = gen_key(curve)
    s.sendall(pub)
    secret = ecdh(curve, priv, bytes(recv_exact(s, PUBLEN[curve])))
    aead = make_aead(cipher, derive(secret, session, idx))
    hs = time.perf_counter() - t0
    mss = live_mss(s)
    spf_level = 4 if huntspf4 else (3 if huntspf3 else (2 if huntspf2 else (1 if huntspf else 0)))
    if cipher == "stream":
        rec = min(rec, mss) if rec > 0 and mss else (mss or 1448)
    else:
        available = fit_record(1 << 20, mss, REC.size + (TAG if aead else 0))
        if rs42:
            received_count = shard_mask.bit_count()
            compound_capacity = (available // received_count) * 4
            maximum = compound_capacity // max(1, spf_level)
            if spf_level >= 3:
                maximum = (maximum // 4) * 4
            rec = min(rec, maximum) if rec > 0 else maximum
            rec = max(4, (rec // 4) * 4)
        else:
            rec = min(rec, available) if rec > 0 else available
            if spf_level >= 3:
                rec = max(1, rec // spf_level)
    ctr = 0

    def emit(seq, payload):
        nonlocal ctr
        hdr = REC.pack(seq, len(payload))
        body = aead.encrypt(nonce(idx, ctr), payload, hdr) if aead else payload
        ctr += 1
        s.sendall(hdr + body)

    if rs42 and spf_level >= 3:
        emit(SPF_RS42_RECORD, bytes((spf_level, shard_mask)) +
             pack_spf_control(hi - lo, spf_level))
    elif rs42:
        emit(RS42_RECORD, RS42.pack(shard_mask, hi - lo))
    elif spf_level >= 2:
        kind = {2: SPF2_RECORD, 3: SPF3_RECORD, 4: SPF4_RECORD}[spf_level]
        emit(kind, pack_spf_control(hi - lo, spf_level))
    elif spf_level == 1:
        emit(SPF_RECORD, SPF.pack(SPF_C0, hi - lo))
    else:
        emit(SUMMARY_RECORD, SUMMARY.pack(hi - lo))
    if cipher == "stream":
        emit(CHECKPOINT_RECORD, struct.pack("!I", ckpt))
        kctr, kmac = stream_keys(secret, session, idx)
        enc = aes_ctr(kctr).encryptor()
        fd = os.open(path, os.O_RDONLY)
        off, k = lo, 0
        while off < hi:
            block = os.pread(fd, min(ckpt, hi - off), off)
            mv, m = memoryview(block), ckpt_mac(kmac, k)
            for i in range(0, len(block), rec):     # rec=1 -> one byte per send() call
                ct = enc.update(mv[i:i + rec])
                s.sendall(ct); m.update(ct); ctr += 1
            s.sendall(m.digest()[:TAG])
            off += len(block); k += 1
        os.close(fd)
        recv_exact(s, 2)
        s.close()
        out.put((idx, hs, ctr, mss, rec))
        return
    fd = os.open(path, os.O_RDONLY)
    off, seq = lo, 0
    while off < hi:
        chunk = os.pread(fd, min(rec, hi - off), off)
        if rs42:
            compound = b"".join(spf_arms(chunk, spf_level)) if spf_level >= 3 else chunk
            shards = rs42_encode(compound)
            payload = b"".join(shards[i] for i in range(6) if shard_mask & (1 << i))
        else:
            payload = b"".join(spf_arms(chunk, spf_level)) if spf_level >= 3 else chunk
        emit(seq, payload)
        off += len(chunk); seq += 1
    os.close(fd)
    emit(seq, b"")
    recv_exact(s, 2)                               # receiver has written everything
    s.close()
    out.put((idx, hs, ctr, mss, rec))


def send_file(host, port, path, streams, rec, curve="x25519", cipher="aes256gcm", src=None,
              ckpt=65536, huntspf=False, huntspf2=False, huntspf3=False, huntspf4=False,
              rs42=False, drop_shards=()):
    host, port = parse_target(host, port)
    if cipher == "stream" and (huntspf3 or huntspf4 or rs42):
        raise ValueError("HUNTSPF3, HUNTSPF4, and RS42 require AEAD record mode")
    drops = tuple(sorted(set(drop_shards)))
    if any(i < 0 or i > 5 for i in drops) or len(drops) > 2:
        raise ValueError("RS(4+2) may drop at most two distinct shard indices from 0 through 5")
    if drops and not rs42:
        raise ValueError("--drop-shards requires --RS42")
    shard_mask = sum(1 << i for i in range(6) if i not in drops)
    if not 1 <= streams <= 65535:
        raise ValueError("streams must be from 1 to 65535")
    size = os.path.getsize(path)
    streams = max(1, min(streams, size))        # never more stripes than bytes (tiny/empty files)
    session = os.urandom(16)
    step = -(-size // streams)
    q = CTX.Queue()
    t0 = time.perf_counter()
    procs = [CTX.Process(target=send_stripe, args=(host, port, src, path, session, i, streams,
                                                   i * step, min(size, (i + 1) * step), rec,
                                                   curve, cipher, q, ckpt, huntspf, huntspf2,
                                                   huntspf3, huntspf4, rs42, shard_mask))
             for i in range(streams)]
    for p in procs:
        p.start()
    res = []
    while len(res) < len(procs):                # fail fast if a stripe process dies
        try:
            res.append(q.get(timeout=1))
        except queue.Empty:
            dead = [p for p in procs if p.exitcode not in (None, 0)]
            if dead:
                for p in procs:
                    p.terminate()
                raise RuntimeError(f"{len(dead)} sender stream(s) failed for {path}")
    elapsed = time.perf_counter() - t0
    for p in procs:
        p.join()
    spf_level = 4 if huntspf4 else (3 if huntspf3 else (2 if huntspf2 else (1 if huntspf else 0)))
    arm_factor = ((shard_mask.bit_count() / 4) * max(1, spf_level)
                  if rs42 else max(1, spf_level))
    return {"size": size, "elapsed": elapsed, "handshake_ms": 1000 * max(r[1] for r in res),
            "records": sum(r[2] for r in res), "mss": res[0][3], "record": res[0][4],
            "spf_level": spf_level, "arm_payload_bytes": int(size * arm_factor),
            "session": session.hex(), "rs42": rs42, "shard_mask": shard_mask,
            "received_shards": [i for i in range(6) if shard_mask & (1 << i)]}


# ---------------------------------------------------------------- input expansion
def safe_relname(name):
    """Check a '/'-separated relative name and return it as a local relative path."""
    parts = name.split("/")
    if (not name or name.startswith("/") or "\\" in name or "\x00" in name
            or any(part in ("", ".", "..") for part in parts)):
        raise ValueError(f"unsafe relative name: {name!r}")
    return os.path.join(*parts)


VOLUME_JUNK = {".Spotlight-V100", ".fseventsd", ".Trashes", ".TemporaryItems",
               ".DocumentRevisions-V100", ".redtail-staging"}


def free_bytes(path):
    """Free space on the disk that holds path (or its nearest existing parent)."""
    path = os.path.abspath(path)
    while not os.path.exists(path):
        path = os.path.dirname(path)
    return shutil.disk_usage(path).free


def skip_reason(path):
    """Say why a path is not packed as a regular file."""
    if os.path.islink(path):
        target = os.readlink(path)
        if not os.path.exists(path):
            return f"broken symlink -> {target}"
        return f"symlink -> {target} (add -L to pack what it points to)"
    if not os.path.exists(path):
        return "vanished or unreadable"
    return "special file (pipe, socket or device)"


def expand_inputs(items, recursive=False, exclude=None, follow=False):
    """Turn files and directories into (path, relative name) pairs.

    A file keeps its basename. A directory needs -r, like cp, and keeps its own
    name as the top folder: `-r ./photos` gives photos/a.jpg, photos/2026/b.jpg.
    Symlinks are skipped unless follow=True (-L), which packs the file or folder
    they point to under the link's own name, like cp -L. Special files are always
    skipped. macOS volume metadata folders and the `exclude` folder (the --drop
    target) are left out.
    """
    out, seen = [], set()
    exclude = os.path.realpath(exclude) if exclude else None

    def add(path, rel):
        if rel in seen:
            raise ValueError(f"two inputs map to the same name: {rel}")
        seen.add(rel)
        out.append((path, rel))

    def unreadable(err):
        print(f"skip unreadable: {err.filename}", file=sys.stderr)

    for item in items:
        if os.path.islink(item) and not follow:
            print(f"skip {item}: {skip_reason(item)}", file=sys.stderr)
        elif os.path.isfile(item):
            add(item, os.path.basename(os.path.normpath(item)))
        elif not os.path.isdir(item):
            raise ValueError(f"not a file or directory: {item}")
        elif not recursive:
            raise ValueError(f"{item} is a directory (add -r to include it)")
        else:
            top = os.path.basename(os.path.abspath(item)) or "root"
            visited = {os.path.realpath(item)}        # guards -L against symlink loops
            for root, dirs, files in os.walk(item, onerror=unreadable, followlinks=follow):
                keep = []
                for d in sorted(dirs):
                    full = os.path.join(root, d)
                    real = os.path.realpath(full)
                    if d in VOLUME_JUNK or (exclude and real == exclude):
                        continue
                    if os.path.islink(full):
                        if not follow:
                            print(f"skip {full}: {skip_reason(full)}", file=sys.stderr)
                            continue
                        if real in visited:
                            print(f"skip {full}: symlink loop", file=sys.stderr)
                            continue
                    visited.add(real)
                    keep.append(d)
                dirs[:] = keep
                for name in sorted(files):
                    path = os.path.join(root, name)
                    if (os.path.islink(path) and not follow) or not os.path.isfile(path):
                        print(f"skip {path}: {skip_reason(path)}", file=sys.stderr)
                        continue
                    rel = os.path.relpath(path, item).replace(os.sep, "/")
                    add(path, f"{top}/{rel}")
    if not out:
        raise ValueError("no regular files found in the inputs")
    return out


# ---------------------------------------------------------------- blob container
def build_blob(items):
    """Build one uncompressed XBL1 container and return its temporary path.

    items are paths (stored by basename) or (path, relative name) pairs from
    expand_inputs; relative names may contain '/' to keep folder structure.
    """
    entries, seen = [], set()
    for item in items:
        path, name = item if isinstance(item, tuple) else (item, os.path.basename(os.path.normpath(item)))
        if not os.path.isfile(path):
            raise ValueError(f"blob input is not a regular file: {path}")
        safe_relname(name)
        encoded = name.encode("utf-8")
        if len(encoded) > 4096:
            raise ValueError(f"blob name longer than 4096 bytes: {name!r}")
        if name in seen:
            raise ValueError(f"duplicate blob name: {name}")
        seen.add(name)
        entries.append((path, encoded, os.path.getsize(path)))
    tmp = tempfile.NamedTemporaryFile(prefix="xmt4-", suffix=".blob", delete=False)
    try:
        with tmp:
            tmp.write(BLOB_HEAD.pack(BLOB_MAGIC, len(entries)))
            for path, name, size in entries:
                tmp.write(BLOB_ENTRY.pack(len(name), size))
                tmp.write(name)
                with open(path, "rb") as src:
                    while block := src.read(1 << 20):
                        tmp.write(block)
        return tmp.name
    except Exception:
        try:
            os.remove(tmp.name)
        except FileNotFoundError:
            pass
        raise


def unpack_blob(path, outdir):
    """Safely unpack an XBL1 container without overwriting existing files."""
    os.makedirs(outdir, exist_ok=True)
    outputs, seen = [], set()
    with open(path, "rb") as src:
        magic, count = BLOB_HEAD.unpack(recv_file_exact(src, BLOB_HEAD.size))
        if magic != BLOB_MAGIC:
            raise ValueError(f"{path!r} is not an XBL1 blob (header={magic!r}); "
                             "use the session ID printed by a send command with --blob")
        if count > 100000:
            raise ValueError(f"{path!r} declares too many XBL1 entries: {count}")
        for _ in range(count):
            name_len, size = BLOB_ENTRY.unpack(recv_file_exact(src, BLOB_ENTRY.size))
            if not 0 < name_len <= 4096:
                raise ValueError("invalid XBL1 filename length")
            name = bytes(recv_file_exact(src, name_len)).decode("utf-8")
            if name in seen:
                raise ValueError(f"duplicate XBL1 filename: {name!r}")
            seen.add(name)
            target = os.path.join(outdir, safe_relname(name))
            parent = os.path.dirname(target)
            os.makedirs(parent, exist_ok=True)
            root = os.path.realpath(outdir)
            if os.path.commonpath([root, os.path.realpath(parent)]) != root:
                raise ValueError(f"XBL1 entry escapes the output directory: {name!r}")
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                remaining = size
                while remaining:
                    block = recv_file_exact(src, min(1 << 20, remaining))
                    os.write(fd, block)
                    remaining -= len(block)
            finally:
                os.close(fd)
            outputs.append(target)
        if src.read(1):
            raise ValueError("trailing bytes after XBL1 entries")
    return outputs


def recv_file_exact(fileobj, n):
    data = bytearray()
    while len(data) < n:
        block = fileobj.read(n - len(data))
        if not block:
            raise ValueError("truncated XBL1 blob")
        data.extend(block)
    return bytes(data)


# ---------------------------------------------------------------- local drop
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(1 << 20):
            h.update(block)
    return h.digest()


def send_report(label, r):
    if r["size"] < 1 << 20:
        amount = f"{r['size']} B"
        rate = f"{r['size'] / max(r['elapsed'], 1e-9) / 1024:.1f} KiB/s"
    else:
        amount = f"{r['size'] / 2**20:.1f} MiB"
        rate = f"{r['size'] / r['elapsed'] / 1e6:.1f} MB/s"
    line = (f"{label} -> {r['session']}.bin: path MSS {r['mss']} B -> record {r['record']} B | "
            f"{r['records']} records | {amount} in {r['elapsed']:.3f}s = {rate}")
    if r["spf_level"] >= 3 and r["rs42"]:
        line += (f" | SPF{r['spf_level']}+RS42 shards {r['received_shards']} payload "
                 f"{r['arm_payload_bytes'] / 2**20:.1f} MiB")
    elif r["spf_level"] >= 3:
        line += f" | SPF{r['spf_level']} arm payload {r['arm_payload_bytes'] / 2**20:.1f} MiB"
    elif r["rs42"]:
        line += f" | RS42 shards {r['received_shards']} payload {r['arm_payload_bytes'] / 2**20:.1f} MiB"
    return line


def local_drop(jobs, dest, streams=1, **send_kw):
    """Run the full XMT4 pipeline over loopback into a local folder (an SSD, say).

    Every job goes through the same handshake, AEAD records, SPF arms and RS42
    shards as a network send. The receiver stages into DEST/.redtail-staging on
    the same disk, each result is checked against the source by SHA-256, then
    moved to DEST/<relative name>. Existing files are never replaced; a mismatch
    stays in staging for inspection. Returns (placed, failed) lists.
    """
    dest = os.path.abspath(dest)
    targets = [os.path.join(dest, safe_relname(rel)) for _, _, rel in jobs]
    clashes = [t for t in targets if os.path.lexists(t)]
    if clashes:
        raise ValueError(f"{len(clashes)} target(s) already exist, e.g. {clashes[0]}")
    sizes = [os.path.getsize(path) for _, path, _ in jobs]
    need = sum(sizes) + max(sizes)                # results plus one part+assembly overlap
    have = free_bytes(dest)
    if need > have:
        raise ValueError(f"--drop needs about {need / 1e9:.1f} GB free on {dest}, "
                         f"only {have / 1e9:.1f} GB available")
    stage = os.path.join(dest, ".redtail-staging")
    rx = Receiver("127.0.0.1", 0, stage, max(2, streams))
    port = rx.lsock.getsockname()[1]
    placed, failed = [], []
    t0 = time.perf_counter()
    try:
        for (label, path, _), target in zip(jobs, targets):
            r = send_file("127.0.0.1", port, path, streams, **send_kw)
            v = rx.collect()
            ok = v["ok"] and sha256_file(v["path"]) == sha256_file(path)
            if ok:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                os.replace(v["path"], target)
                placed.append(target)
            else:
                failed.append(v["path"])
            print(f"{send_report(label, r)} | {'SHA-256 OK' if ok else 'MISMATCH (kept in staging)'}",
                  flush=True)
    finally:
        rx.close()
        try:
            os.rmdir(stage)                       # only succeeds when nothing failed
        except OSError:
            pass
    total = sum(os.path.getsize(p) for p in placed)
    elapsed = time.perf_counter() - t0
    print(f"drop: {len(placed)} placed, {len(failed)} failed, {total / 2**20:.1f} MiB "
          f"in {elapsed:.2f}s -> {dest}", flush=True)
    return placed, failed


def probe_mss(target, port):
    """Open one TCP connection to a running receiver, read the negotiated MSS, hang up."""
    host, port = parse_target(target, port)
    with socket.create_connection((host, port), timeout=5) as s:
        return live_mss(s), host


# ---------------------------------------------------------------- PDU math
ETH_WIRE = 14 + 4 + 8 + 12           # Ethernet hdr + FCS + preamble/SFD + inter-frame gap
OVERHEAD = REC.size + TAG            # 28 B per sealed record


def pdu_table(mtus, v6=False, live=None):
    fam = "IPv6" if v6 else "IPv4"
    rows = [(f"MTU {m} / {fam}", m, mss_for_mtu(m, v6)) for m in mtus]
    if live:
        mss, host = live
        rows.insert(0, (f"LIVE path to {host}", mss + (60 if v6 else 40) + TS_OPT, mss))
    print(f"Per-packet math ({fam}, TCP timestamps on)\n")
    print(f"{'link':28}{'MTU':>7}{'TCP payload':>13}{'on wire':>9}{'goodput':>9}"
          f"{'auto record':>13}{'file bytes':>12}")
    for label, mtu, mss in rows:
        wire = mtu + ETH_WIRE
        rec = fit_record(1 << 20, mss, OVERHEAD)
        eff = rec / (rec + OVERHEAD) * mss / wire
        print(f"{label:28}{mtu:>7}{mss:>13}{wire:>9}{mss / wire:>9.2%}{rec:>13}{eff:>12.2%}")
    print("\n'auto record' = one XMT record fitted inside one negotiated TCP segment.")
    print("Live MSS comes from TCP_MAXSEG on a real connection, so it already reflects the")
    print("smaller of the two ends' MTUs (and any VPN/PPPoE/tunnel clamp along the way).")
    _, mtu, mss = rows[0]
    rec = fit_record(1 << 20, mss, OVERHEAD)
    eff = rec / (rec + OVERHEAD) * mss / (mtu + ETH_WIRE)
    print(f"\nLine-rate ceilings for file bytes at {rows[0][0]}:")
    for name, gbps in (("1 GbE", 1), ("10 GbE", 10), ("25 GbE", 25), ("100 GbE", 100)):
        mbs = gbps * 1e9 / 8 * eff / 1e6
        print(f"  {name:8} {mbs:9.1f} MB/s   1 GiB file in {(1 << 30) / (mbs * 1e6):6.2f} s")


# ---------------------------------------------------------------- bench
def bench(a):
    os.makedirs(a.workdir, exist_ok=True)
    src = a.file or os.path.join(a.workdir, f"payload_{a.size_mib}MiB.bin")
    if not a.file and not os.path.exists(src):
        with open(src, "wb") as f:
            for _ in range(a.size_mib):
                f.write(os.urandom(1 << 20))       # random = max Shannon entropy, incompressible
    outdir = os.path.join(a.workdir, "rebuilt")
    rx = Receiver(a.dst, a.port, outdir, max(a.streams))
    rows = []
    print(f"file={src}  {os.path.getsize(src) / 2**20:.0f} MiB   {a.src} -> {a.dst}:{a.port}\n")
    print(f"{'cipher':>10}{'curve':>8}{'record':>9}{'streams':>8}{'time s':>9}{'MB/s':>9}{'Gbit/s':>8}"
          f"{'hs ms':>8}{'records':>9}{'man':>5}{'coord':>7}{'sum':>5}  assembly")
    try:
        for cipher in a.ciphers:
            for curve in a.curves:
                for rec in a.records:
                    for n in a.streams:
                        r = send_file(a.dst, a.port, src, n, rec, curve, cipher,
                                      src=a.src, ckpt=a.checkpoint)
                        v = rx.collect()
                        os.remove(v["path"])
                        mbs = r["size"] / r["elapsed"] / 1e6
                        row = dict(cipher=cipher, curve=curve, record=r["record"], streams=n,
                                   seconds=round(r["elapsed"], 3), MBps=round(mbs, 1),
                                   Gbps=round(mbs * 8 / 1000, 2), handshake_ms=round(r["handshake_ms"], 2),
                                   records=r["records"], manifest_records=v["manifest_records"],
                                   coordinate_records=v["coordinate_records"],
                                   summary_records=v["summary_records"], verified=v["ok"])
                        rows.append(row)
                        print(f"{cipher:>10}{curve:>8}{r['record']:>9}{n:>8}{row['seconds']:>9}{row['MBps']:>9}"
                              f"{row['Gbps']:>8}{row['handshake_ms']:>8}{row['records']:>9}"
                              f"{row['manifest_records']:>5}{row['coordinate_records']:>7}"
                              f"{row['summary_records']:>5}  "
                              f"{'OK' if v['ok'] else 'INVALID'}", flush=True)
    finally:
        rx.close()
    if a.csv:
        new = not os.path.exists(a.csv)
        with open(a.csv, "a", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            if new:
                w.writeheader()
            w.writerows(rows)


class CLIHelpFormatter(argparse.ArgumentDefaultsHelpFormatter,
                       argparse.RawDescriptionHelpFormatter):
    pass


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=CLIHelpFormatter,
                                 allow_abbrev=False)
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("pdu", help="per-packet math; --to probes a live receiver's real MSS",
                       description="Calculate XMT record sizes and link-efficiency ceilings.",
                       formatter_class=CLIHelpFormatter, allow_abbrev=False)
    d.add_argument("--mtu", type=int, nargs="+", default=[1500, 9000],
                   help="MTUs to tabulate (e.g. 1280 1400 1500 9000)")
    d.add_argument("--ipv6", action="store_true", help="use IPv6 header sizes")
    d.add_argument("--to", help="host[:port] of a running receiver to measure the live path")
    d.add_argument("--port", type=int, default=47000, help="receiver port used by --to")
    b = sub.add_parser("bench", help="run a local receiver/sender parameter sweep",
                       description="Benchmark record sizes, stream counts, ciphers, and curves on loopback.",
                       formatter_class=CLIHelpFormatter, allow_abbrev=False)
    b.add_argument("--size-mib", type=int, default=256, help="generated fixture size when --file is omitted")
    b.add_argument("--file", help="existing source file instead of a generated random fixture")
    b.add_argument("--workdir", default="/dev/shm/matter", help="fixture and temporary receiver directory")
    b.add_argument("--src", default="127.0.0.1", help="sender source address")
    b.add_argument("--dst", default="127.0.0.2", help="loopback receiver address")
    b.add_argument("--port", type=int, default=47000, help="loopback receiver port")
    b.add_argument("--records", type=int, nargs="+", default=[0],
                   help="requested plaintext bytes; capped to one live TCP segment; 0 = maximum fit")
    b.add_argument("--streams", type=int, nargs="+", default=[1, 2, 4, 8], help="parallel stream counts to sweep")
    b.add_argument("--ciphers", nargs="+", default=["aes256gcm"], choices=CIPHERS,
                   help="cipher modes to sweep")
    b.add_argument("--curves", nargs="+", default=["x25519"], choices=CURVES,
                   help="ECDH curves to sweep")
    b.add_argument("--checkpoint", type=int, default=65536, help="stream mode: bytes per HMAC tag")
    b.add_argument("--csv", help="append benchmark rows to this CSV file")
    r = sub.add_parser("recv", help="listen for XMT sessions and rebuild outputs",
                       description="Run the XMT4 receiver. It auto-detects record and checkpoint modes.",
                       formatter_class=CLIHelpFormatter, allow_abbrev=False)
    r.add_argument("--bind", default="0.0.0.0", help="local listen address")
    r.add_argument("--port", type=int, default=47000, help="local listen port")
    r.add_argument("--out", default="./rebuilt", help="directory for session outputs and temporary parts")
    r.add_argument("--workers", type=int, default=8, help="receiver worker process count")
    r.add_argument("--mode", help="ignored: the receiver auto-detects record/stream per connection")
    r.add_argument("--clamp-mss", type=int, help="advertise a smaller MSS to simulate a small-MTU path")
    s = sub.add_parser("send", help="send files, blobs, SPF arms, or RS42 shards",
                       description="Send files or folders (-r) to a receiver (--to) or a local folder (--drop), "
                                   "one XMT session per file, or one session with --blob.",
                       epilog=SEND_EXAMPLES,
                       formatter_class=CLIHelpFormatter, allow_abbrev=False)
    s.add_argument("files", nargs="+",
                   help="files or folders (folders need -r); each file is an independent XMT session")
    s.add_argument("-r", "--recursive", action="store_true",
                   help="include folders and everything under them, keeping the folder structure")
    s.add_argument("-L", "--follow-links", action="store_true", dest="follow_links",
                   help="pack the files and folders symlinks point to, like cp -L (default: skip links)")
    where = s.add_mutually_exclusive_group(required=True)
    where.add_argument("--to", help="receiver host or host:port")
    where.add_argument("--drop", metavar="DIR",
                       help="local file drop: run the same pipeline over loopback into DIR "
                            "(an SSD mount, say), verify each file by SHA-256, keep relative paths")
    s.add_argument("--port", type=int, default=47000, help="receiver port when --to omits one")
    s.add_argument("--streams", type=int, default=1,
                   help="parallel TCP streams; default 1 (best measured Raspberry Pi path)")
    s.add_argument("--record", type=int, default=0,
                   help="requested plaintext bytes; capped to one live TCP segment; 0 = maximum fit")
    s.add_argument("--cipher", default="aes256gcm", choices=CIPHERS,
                   help="record-mode cipher; --mode stream selects checkpoint encryption")
    s.add_argument("--mode", default="record", choices=["record", "stream"],
                   help="record = sealed records; stream = raw AES-CTR bytes + HMAC tag per checkpoint")
    s.add_argument("--checkpoint", type=int, default=65536, help="stream mode: bytes per HMAC tag")
    s.add_argument("--curve", default="x25519", choices=CURVES, help="ephemeral ECDH curve")
    spf = s.add_mutually_exclusive_group()
    spf.add_argument("--HUNTSPF", "--HUNTSPF1", action="store_true", dest="hunt_spf",
                     help="XMT4: send the formal minimal C0+length control before data")
    spf.add_argument("--HUNTSPF2", action="store_true", dest="hunt_spf2",
                     help="XMT4: send C0 length and its validated GF(256) C1 arm")
    spf.add_argument("--HUNTSPF3", action="store_true", dest="hunt_spf3",
                     help="XMT4: transmit and validate full C0+C1+C2 payload arms")
    spf.add_argument("--HUNTSPF4", action="store_true", dest="hunt_spf4",
                     help="XMT4: transmit and validate full C0+C1+C2+C3 payload arms")
    s.add_argument("--RS42", action="store_true", dest="rs42",
                   help="systematic Reed-Solomon 4+2; composes with HUNTSPF3/4")
    s.add_argument("--drop-shards", type=int, nargs="*", default=[], metavar="N",
                   help="RS42 experiment: omit up to two shard indices (0 through 5)")
    s.add_argument("--blob", action="store_true",
                   help="1337-OP MODE: pack all files into one uncompressed XBL1 session")
    u = sub.add_parser("unpack-blob", allow_abbrev=False,
                       help="1337-OP MODE: safely unpack one received XBL1 container",
                       description="Extract an XBL1 blob without path traversal or overwriting files.",
                       formatter_class=CLIHelpFormatter)
    u.add_argument("blob", help="received XBL1 session file")
    u.add_argument("--out", required=True, help="new or existing extraction directory")
    if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
        print(ap.format_help().rstrip())
        for name, parser in sub.choices.items():
            print(f"\n{'=' * 12} {name} settings {'=' * 12}")
            print(parser.format_help().rstrip())
        print(f"\nQuick start:\n  {QUICK_START}\n  "
              "python3 redtail.py send -r ./dir --drop /Volumes/SSD/test --RS42 --drop-shards 2 3")
        return
    a = ap.parse_args()

    if a.cmd == "pdu":
        live = None
        if a.to:
            try:
                live = probe_mss(a.to, a.port)
            except OSError as e:
                print(f"could not probe {a.to}: {e} (is `recv` running there?)\n", file=sys.stderr)
        pdu_table(a.mtu, a.ipv6, live)
    elif a.cmd == "bench":
        bench(a)
    elif a.cmd == "recv":
        if a.mode:
            print("note: --mode is chosen by the sender; this receiver handles both", file=sys.stderr)
        rx = Receiver(a.bind, a.port, a.out, a.workers, a.clamp_mss)
        print(f"listening on {a.bind}:{a.port} -> {a.out}", flush=True)
        while True:
            print(rx.collect(), flush=True)
    elif a.cmd == "unpack-blob":
        try:
            for output in unpack_blob(a.blob, a.out):
                print(output)
        except (OSError, UnicodeError, ValueError) as error:
            ap.error(str(error))
    else:
        cipher = "stream" if a.mode == "stream" else a.cipher
        if a.rs42 and (a.hunt_spf or a.hunt_spf2):
            ap.error("--HUNTSPF/--HUNTSPF2 are not applied under --RS42; "
                     "use --HUNTSPF3 or --HUNTSPF4 to compose, or leave it off")
        try:
            entries = expand_inputs(a.files, a.recursive, exclude=a.drop, follow=a.follow_links)
        except ValueError as error:
            ap.error(str(error))
        if a.blob:
            total = sum(os.path.getsize(path) for path, _ in entries)
            if total > free_bytes(tempfile.gettempdir()):
                ap.error(f"--blob builds a {total / 1e9:.1f} GB temporary container in "
                         f"{tempfile.gettempdir()}, which lacks the space; set TMPDIR to a "
                         "disk that has it")
            print(f"blob: {len(entries)} files, {total / 1e9:.2f} GB", flush=True)
        blob_path = build_blob(entries) if a.blob else None
        if blob_path:
            jobs = [(f"blob[{len(entries)} files]", blob_path,
                     time.strftime("redtail-blob-%Y%m%d-%H%M%S.xbl1"))]
        else:
            jobs = [(rel if a.drop else path, path, rel) for path, rel in entries]
        send_kw = dict(rec=a.record, curve=a.curve, cipher=cipher, ckpt=a.checkpoint,
                       huntspf=a.hunt_spf, huntspf2=a.hunt_spf2, huntspf3=a.hunt_spf3,
                       huntspf4=a.hunt_spf4, rs42=a.rs42, drop_shards=a.drop_shards)
        try:
            if a.drop:
                try:
                    placed, failed = local_drop(jobs, a.drop, a.streams, **send_kw)
                except ValueError as error:
                    ap.error(str(error))
                if blob_path and placed:
                    print(f"unpack with: {sys.argv[0]} unpack-blob {placed[0]} --out DIR")
                if failed:
                    sys.exit(f"{len(failed)} file(s) failed verification")
            else:
                for label, path, _ in jobs:
                    print(send_report(label, send_file(a.to, a.port, path, a.streams, **send_kw)),
                          flush=True)
        finally:
            if blob_path:
                os.remove(blob_path)

if __name__ == "__main__":
    main()
