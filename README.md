# DarkRock TCP / XMT4

XMT4 is an experimental Python file transport for studying authenticated TCP
records, compact control fields, GF(256) transforms, and Reed–Solomon 4+2
erasure recovery. It is a lab implementation, not a production transfer or
detection product.

The measured Mac-to-Raspberry-Pi path carried about 12–12.6 MB/s of total arm
traffic. Ordinary one-stream transfers delivered about 12.5 MB/s of source
data. Full SPF and RS redundancy consumed the same channel capacity while
reducing source-data goodput in proportion to expansion.

See [XMT4_LAB_REPORT.md](XMT4_LAB_REPORT.md) for the definition tree,
protocol contract, commands, full results, negative results, and limitations.

## Requirements

- Python 3.10+
- `cryptography`
- macOS or Linux for the tested multiprocessing path

```bash
python3.10 -m pip install -r requirements.txt
```

Show the complete command and settings reference:

```bash
python3.10 redtail.py -h
```

Subcommand help remains available, for example `redtail.py send -h`.

## Start a receiver

```bash
python3.10 redtail.py recv \
  --bind 0.0.0.0 \
  --port 47000 \
  --out ./rebuilt
```

The receiver can also run ephemerally through SSH without saving the program
on the remote host:

```bash
ssh -T admin@REMOTE_HOST \
  'mkdir -p "$HOME/xmt-rebuilt" && python3.10 - recv \
  --bind 0.0.0.0 --port 47000 --out "$HOME/xmt-rebuilt"' \
  < redtail.py
```

## Send files

```bash
python3.10 redtail.py send file.bin \
  --to REMOTE_HOST:47000
```

Multiple files are independent sessions:

```bash
python3.10 redtail.py send a.bin b.bin c.bin \
  --to REMOTE_HOST:47000
```

The sender prints the session-to-output mapping. Filenames are not placed on
the wire.

XMT4 does not compress files. By default every input is an independent session.
`--blob` (**1337-OP MODE**) creates one uncompressed XBL1 container, sends it as one session, and
stores safe basenames and lengths so it can be unpacked later:

```bash
python3.10 redtail.py send a.bin b.bin c.bin \
  --to REMOTE_HOST:47000 --blob

python3.10 redtail.py unpack-blob RECEIVED_SESSION.bin \
  --out ./unpacked
```

Blob mode uses a temporary local container equal to approximately the combined
input size. Use `tar` or ZIP before XMT when compression or broader archive
metadata is required.

## Experimental modes

```bash
# Minimal formal C0 control
python3.10 redtail.py send file.bin --to HOST:47000 --HUNTSPF1

# Full C0+C1+C2 field validation
python3.10 redtail.py send file.bin --to HOST:47000 --HUNTSPF3

# Reed–Solomon 4+2
python3.10 redtail.py send file.bin --to HOST:47000 --RS42

# Prove recovery with two omitted shards
python3.10 redtail.py send file.bin --to HOST:47000 \
  --RS42 --drop-shards 2 3

# Compose SPF3 with RS42
python3.10 redtail.py send file.bin --to HOST:47000 \
  --HUNTSPF3 --RS42 --drop-shards 2 3
```

`--drop-shards` is a controlled application-level erasure experiment. TCP
continues to handle network packet loss through retransmission.

## Tests

```bash
python3.10 -m unittest discover -s tests -v
python3.10 -m py_compile redtail.py
```

## Security boundary

Records are encrypted and authenticated, but the ephemeral ECDH handshake does
not authenticate peer identity. Use a trusted network or an authenticated
outer channel when peer identity matters. XMT4 does not transmit a filename or
whole-file hash, and sender timing ends after stream acknowledgements rather
than after receiver-side final concatenation.
