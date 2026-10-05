# XMT4 Transport and Erasure Lab Report

**Date:** 2026-10-04
**Environment:** macOS sender, Raspberry Pi receiver, Wi-Fi LAN
**Scope:** school and engineering lab experiment

## 1. Purpose

This lab measured a Python TCP file transport while progressively adding
authenticated framing, compact control fields, deterministic GF(256) arms, and
Reed–Solomon 4+2 erasure recovery.

The experiment separates three questions:

1. How much source data can the path deliver?
2. How much total encoded arm traffic can the path carry?
3. What CPU cost appears when the receiver must reconstruct missing shards?

XMT4 is not a SIEM, EDR, malware detector, covert transport, or production file
transfer product. HUNTSPF is the experiment's historical flag name; these modes
validate declared algebraic relationships and do not hunt endpoint content.

## 2. Definition tree

```text
XMT4 (Matter Transport version 4)
├── Session
│   ├── random 128-bit session identifier
│   ├── one or more TCP streams
│   └── receiver output: <session-id>.bin
├── TCP stream count: --streams N
│   ├── N independent TCP connections
│   ├── contiguous source stripes
│   └── default N=1 (fastest measured Raspberry Pi setting)
├── Cryptographic handshake
│   ├── ephemeral X25519 (default) or P-256
│   ├── HKDF-SHA256 per session and stream
│   └── limitation: no peer-identity authentication
├── Record mode (default)
│   ├── sequence number: 64 bits
│   ├── ciphertext length: 32 bits
│   ├── AES-256-GCM or ChaCha20-Poly1305
│   ├── 16-byte authentication tag
│   └── one record fitted to negotiated TCP MSS
├── Checkpointed stream mode: --mode stream
│   ├── AES-CTR continuous encryption
│   ├── HMAC-SHA256 tag per checkpoint
│   └── separate from --streams N
├── Minimal summary
│   ├── authenticated stream byte count
│   ├── no filename
│   ├── no absolute file coordinates
│   ├── no whole-file SHA-256
│   └── receiver completion_flag=1 after assembly
├── Blob mode: --blob
│   ├── XBL1 uncompressed container
│   ├── one XMT session for multiple files
│   ├── safe basenames and 64-bit lengths
│   └── explicit unpack-blob command
├── SPF controls
│   ├── HUNTSPF / HUNTSPF1: C0 length vector
│   ├── HUNTSPF2: C0+C1 control; C1=2×C0 in GF(256)
│   ├── HUNTSPF3: full C0+C1+C2 payload arms
│   └── HUNTSPF4: full C0+C1+C2+C3 payload arms
├── GF(256)
│   ├── field polynomial: 0x11d
│   ├── C1=2×C0
│   ├── C2=4×C0
│   ├── C3=8×C0
│   └── zero elimination: disabled
└── RS42: systematic Reed–Solomon 4+2
    ├── D0 [1 0 0 0]
    ├── D1 [0 1 0 0]
    ├── D2 [0 0 1 0]
    ├── D3 [0 0 0 1]
    ├── P0 [1 1 1 1]
    ├── P1 [1 2 4 8]
    ├── reconstructs any two omitted shards
    └── composes with HUNTSPF3 or HUNTSPF4
```

## 3. Key terms

### XMT

Project-specific shorthand for Matter Transport. It is not an industry
standard.

### AEAD

Authenticated Encryption with Associated Data. XMT4 encrypts each record and
authenticates its sequence and length header as associated data.

### Stream versus streams

- `--mode stream` selects continuous AES-CTR encryption with periodic HMAC
  checkpoints.
- `--streams N` selects the number of parallel TCP connections.

They are independent settings. On the Raspberry Pi path, one TCP stream was
usually faster and more stable than four.

Neither setting performs compression. By default every source file is an
independent XMT session. Multiple TCP streams are reassembled into that one
file, while multiple inputs remain separate receiver outputs unless `--blob`
is selected.

### Blob mode

`--blob` packages multiple inputs into one uncompressed XBL1 container and one
XMT session. XBL1 stores each safe basename and 64-bit byte length followed by
the file bytes. `unpack-blob` refuses path components, duplicate names,
truncation, trailing data, and overwriting existing outputs.

Blob mode deliberately transmits basenames. Ordinary multi-file mode does not.
The sender creates a temporary local blob approximately equal to the combined
input size and removes it after the transfer attempt.

### SPF arm

An experiment-specific GF(256) field arm. The name does not claim a standard
shortest-path algorithm. C1, C2, and C3 are deterministic transforms of C0.

### Reed–Solomon 4+2

Four systematic data shards and two parity shards. Any four of the six rows are
sufficient to recover the original four data shards for this generator.

### Erasure

A known missing shard. `--drop-shards` omits selected application shards before
transmission so the decoder can be tested deterministically. It does not inject
IP packet loss.

### Shannon entropy

The current 64 MiB random fixture measured **7.999997306 bits/byte**, or
**99.999966322%** of the eight-bit byte ceiling. Nonzero GF(256) transforms are
reversible, so every arm retains the same marginal entropy. Derived arms add
redundancy but no new joint information:

```text
H(C0,C1,C2,...) = H(C0)
```

## 4. Wire contract

### Handshake

Each TCP connection sends an XMT4 hello containing the session identifier,
stream index, stream count, curve selection, and cipher selection. Each stream
performs its own ephemeral ECDH exchange and derives a unique key with
HKDF-SHA256.

### AEAD record

```text
sequence u64 | ciphertext_length u32 | ciphertext | tag 16 bytes
```

The 12-byte header is authenticated as AEAD associated data. The nonce is the
four-byte stream index followed by the eight-byte encryption-record counter.

On the measured 1500-byte IPv4 path:

```text
TCP MSS:                1448 bytes
record header + tag:      28 bytes
ordinary source record: 1420 bytes
```

### Assembly

The receiver writes each authenticated stream to an isolated part file, orders
parts by stream index, and concatenates them. A local result reports
`complete=true` and `completion_flag=1`. Filenames are not transmitted; the
sender prints the session identifier that becomes the receiver filename.

## 5. Mode expansion

| Mode | Full payload arms | Approximate payload factor |
|---|---:|---:|
| Ordinary / SPF1 / SPF2 | 1 | 1× |
| SPF3 | 3 | 3× |
| SPF4 | 4 | 4× |
| RS42, all shards | 6 shards for 4 data | 1.5× |
| RS42, two omitted | 4 shards for 4 data | 1× |
| SPF3 + RS42, all shards | 3 × 1.5 | 4.5× |
| SPF3 + RS42, two omitted | 3 × 1 | 3× |

## 6. Fixtures

The generated binary fixtures are excluded from Git.

| Fixture | Bytes | SHA-256 |
|---|---:|---|
| random_1MiB.bin | 1,048,576 | `13ad6719e0f8b5a99cd7a878aa825e95600799d677434783cebec38815ccd864` |
| random_4MiB.bin | 4,194,304 | `eeb4e6598f95d8da4462821b4bbc650544d584d53444c94cc7e82135528c4e6a` |
| random_16MiB.bin | 16,777,216 | `53917a81a02cb0f15bc2bc8f4f5464fbf0a2bba02fbf998e5c83b61b1842afcb` |
| random_64MiB.bin | 67,108,864 | `a18c8fb3a929f6743ad1e5c33ce5a3a337a0dfc1ee7138489deb038a5a18bbe3` |
| random_64MiB-1.bin | 67,108,864 | `bad0b588de5015dc6657426a0f0668541f12c90f8eacdf870ead8a451ad61f2c` |
| random_64MiB-2.bin | 67,108,864 | `6bdf19748403b7807f86b52dde42128c71e06f39e075fd2f704aca47908a5944` |
| random_1GiB.bin | 1,073,741,824 | `cfbe35a1286a7b6f92a6e6f27f06ea6770f59aa8221e9d89b9dbd626d3a1c6cd` |

Generate fixtures locally:

```bash
dd if=/dev/urandom of=random_64MiB.bin bs=1m count=64
dd if=/dev/urandom of=random_1GiB.bin bs=8m count=128
```

## 7. Baseline measurements

### Localhost, 1 GiB

| Mode | Streams | Throughput |
|---|---:|---:|
| AES-256-GCM records | 4 | 300.5 MB/s |
| AES-CTR/HMAC checkpoints | 4 | 516.6 MB/s |

These are host memory, cryptography, multiprocessing, and filesystem results;
they are not physical-network measurements.

### Mac to Raspberry Pi, 64 MiB

| Mode | Streams | Observed throughput |
|---|---:|---:|
| SCP reference | 1 | 6.8 MB/s |
| AES-256-GCM records | 1 | 12.5–12.7 MB/s |
| ChaCha20-Poly1305 records | 1 | 11.6–12.8 MB/s |
| AES-CTR/HMAC checkpoints | 1 | 12.8 MB/s in one run |
| AES-256-GCM records | 4 | 7.4–11.8 MB/s |

One stream became the default because it was the most repeatable configuration
on the Raspberry Pi path. Wi-Fi distance, walls, interference, retransmissions,
Pi CPU, memory, storage, and Python scheduling all affect these measurements.

## 8. Multi-file and size sweep

Six files totaling 213 MiB were sent as six independent sessions.

| Source size | Ordinary/SPF2 example | SPF3 source goodput | SPF3 arm-adjusted traffic |
|---:|---:|---:|---:|
| 1 MiB | 6.3 MB/s | 3.3 MB/s | 9.9 MB/s |
| 4 MiB | 10.0 MB/s | 3.0 MB/s | 9.0 MB/s |
| 16 MiB | 12.6 MB/s | 3.6 MB/s | 10.8 MB/s |
| 64 MiB | 12.4–12.9 MB/s | 4.1–4.3 MB/s | 12.3–12.9 MB/s |

Small transfers are dominated by handshake and process startup. Larger files
converged near the path's 12–12.6 MB/s encoded-traffic ceiling.

## 9. SPF results

Three separate 64 MiB fixtures produced these averages:

| Mode | Average source goodput | Arm-adjusted traffic |
|---|---:|---:|
| Baseline | 11.73 MB/s | 11.73 MB/s |
| SPF1 | 12.50 MB/s | 12.50 MB/s |
| SPF2 | 12.37 MB/s | 12.37 MB/s |
| SPF3 | 4.20 MB/s | 12.60 MB/s |
| SPF4, one earlier run | 3.10 MB/s | approximately 12.40 MB/s |

SPF1 and SPF2 transform only the short control and have no measurable channel
cost. SPF3 and SPF4 send full deterministic arms. Their source goodput falls in
proportion to the expansion while total arm traffic stays near the same channel
ceiling.

## 10. Reed–Solomon validation

### Codec correctness

The RS42 codec was exercised across:

```text
7 source lengths
1 no-loss pattern
6 single-shard losses
15 double-shard losses
154 exact reconstructions total
```

End-to-end TCP tests also reconstructed exactly with all shards, missing shards
`0,5`, and missing data shards `2,3`.

### Initial negative performance result

The first pure-Python GF combination loop limited the Raspberry Pi:

| RS42 case | Source goodput |
|---|---:|
| All six shards | 3.7 MB/s |
| Missing `0,5` | 2.4 MB/s |
| Missing `2,3` | 1.9 MB/s |

The implementation was changed so identity rows return directly, coefficient
scaling uses translation tables, and XOR combinations use native big-integer
operations. All 154 correctness cases remained exact.

### Optimized results

| Mode | Missing shards | Source goodput | Arm-adjusted traffic |
|---|---|---:|---:|
| RS42 | none | 8.0 MB/s | 12.0 MB/s |
| SPF3 + RS42 | none | 2.8 MB/s | 12.6 MB/s |
| SPF3 + RS42 | `0,5` | 4.0 MB/s | 12.0 MB/s |
| SPF3 + RS42 | `2,3` | 3.4 MB/s | 10.2 MB/s |

The all-shard and one-data-recovery cases reached the network pipeline ceiling
after accounting for expansion. Rebuilding two missing data shards remained
partly CPU limited on the Pi at about 10.2 MB/s of arm-adjusted work.

## 11. Commands

### Ephemeral receiver through SSH

```bash
ssh -T admin@PI_HOST \
  'mkdir -p "$HOME/xmt-rebuilt" && python3.10 - recv \
  --bind 0.0.0.0 --port 47000 --out "$HOME/xmt-rebuilt"' \
  < redtail.py
```

The script is read from SSH standard input and is not saved as a remote program.
Python and the `cryptography` package must already exist on the receiver.

### Ordinary multi-file send

```bash
python3.10 redtail.py send a.bin b.bin c.bin \
  --to PI_HOST:47000
```

### One-session blob send and unpack

```bash
python3.10 redtail.py send a.bin b.bin c.bin \
  --to PI_HOST:47000 --blob

python3.10 redtail.py unpack-blob RECEIVED_SESSION.bin \
  --out ./unpacked
```

### RS42 recovery experiment

```bash
python3.10 redtail.py send random_64MiB.bin \
  --to PI_HOST:47000 \
  --RS42 --drop-shards 2 3
```

### Combined SPF3 and RS42

```bash
python3.10 redtail.py send random_64MiB.bin \
  --to PI_HOST:47000 \
  --HUNTSPF3 --RS42 --drop-shards 2 3
```

### Stop the remote receiver

```bash
ssh admin@PI_HOST 'fuser -k 47000/tcp'
```

## 12. Findings

1. The measured Wi-Fi/Pi path carried approximately 12–12.6 MB/s of encoded arm
   traffic once files were large enough to amortize startup.
2. Deterministic GF arms did not add information. They traded channel capacity
   for validation or recovery structure.
3. SPF3 and SPF4 were negative throughput results but positive field-validation
   results.
4. RS42 recovered all tested single and double erasures exactly.
5. The first Python GF implementation was CPU bound. Native-table and integer-XOR
   changes moved most cases back to the network ceiling.
6. Two missing original shards remained the most expensive Raspberry Pi decode
   case.
7. Parallel TCP streams did not help this receiver. One stream was faster and
   more stable.

## 13. Limitations and honesty rules

- The ECDH handshake is ephemeral but unauthenticated. A network attacker could
  impersonate a peer. Record authentication does not establish peer identity.
- The receiver does not receive the source filename or a whole-file hash.
- Exact equality was established in controlled local tests. Remote runs report
  authenticated stream completion and assembly, not an independently
  transmitted whole-file digest.
- Sender timing ends when stream workers receive their acknowledgements. Final
  receiver concatenation occurs immediately afterward and is not included.
- `--drop-shards` is simulated application erasure. It does not demonstrate
  recovery from missing TCP packets because TCP retransmits those packets.
- RS42 parity and SPF arms are deterministic redundancy. Their marginal entropy
  does not imply additional joint information.
- Throughput results apply to the tested Mac, Raspberry Pi, Wi-Fi conditions,
  Python version, storage, and cipher configuration.
- The code has not undergone a third-party cryptographic or protocol audit.
- The implementation has no resume protocol, congestion-control tuning,
  directory semantics, or production key management. XBL1 basenames are
  authenticated as encrypted blob content, but the outer XMT session still has
  no separate filename metadata.
- Blob mode is uncompressed and requires temporary sender disk space close to
  the combined input size.

## 14. Reproduction checklist

```bash
python3.10 -m pip install -r requirements.txt
python3.10 -m py_compile redtail.py
python3.10 -m unittest discover -s tests -v
python3.10 redtail.py pdu --mtu 1500 9000
```

Record the receiver result fields alongside every performance run:

```text
complete
completion_flag
reason
summary_records / spf_records / rs42_records
spf_control
rs42_received_shards
```
