# RedTail TCP / XMT4

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

## Folders and local file drop

### Folders (`-r`, `-L`)

Folders need `-r`, like `cp`. The folder keeps its own name as the top level,
so `-r ./photos` gives `photos/a.jpg`, `photos/2026/b.jpg`, and so on.

- Symlinks are skipped by default. Each skip says why: a link (and where it
  points), a broken link, or a special file such as a pipe or socket.
- `-L` / `--follow-links` packs what a link points to under the link's own name,
  like `cp -L`. Broken links and folder loops are still skipped. A link to a
  file that is also packed directly is stored twice.
- macOS volume folders (`.Spotlight-V100`, `.fseventsd`, `.Trashes`,
  `.TemporaryItems`, `.DocumentRevisions-V100`) and the `--drop` folder itself
  are left out, so a drive can be packed onto itself.
- Folders that cannot be read are reported and skipped.

### Local file drop (`--drop DIR`)

`--drop DIR` replaces `--to` and runs the same pipeline (handshake, AEAD records,
SPF arms, RS42 shards) over loopback into a local folder, such as an SSD. No
separate receiver is needed. Each file is staged on that disk, checked against
its source by SHA-256, then moved to `DIR/<relative path>`.

- Existing files are never replaced; the run stops before sending if any target
  exists.
- A file that fails verification stays in `DIR/.redtail-staging` for inspection.
- Free space is checked first. The target disk needs about the total size plus
  the largest file (the receiver briefly holds a part and its assembly). With
  `--blob`, the temporary container also needs the total size in `TMPDIR`.
- The disk receives the decoded files, not the RS42 shards: RS42 protects the
  transfer, and the drop proves the round trip.
- XMT4 does not compress. Output size equals input size.

### Examples

```bash
# Pack a folder onto an SSD, one session per file
python3.10 redtail.py send -r ./dir --drop /Volumes/SSD/test

# Same, with RS42 and two shards deliberately dropped
python3.10 redtail.py send -r ./dir --drop /Volumes/SSD/test \
  --RS42 --drop-shards 2 3

# Many small files: one XBL1 container instead of one session each
python3.10 redtail.py send -r ./dir --drop /Volumes/SSD/test --blob
python3.10 redtail.py unpack-blob /Volumes/SSD/test/redtail-blob-*.xbl1 --out ./restored

# Pack a whole drive onto itself, following symlinks
python3.10 redtail.py send -r -L "/Volumes/SSD" \
  --drop "/Volumes/SSD/redtail-test" \
  --blob --RS42 --drop-shards 2 3 --mode record

# Put the --blob temporary container on a disk with room
TMPDIR=/Volumes/Other python3.10 redtail.py send -r ./dir \
  --drop /Volumes/SSD/test --blob

# Folders over the network work the same way
python3.10 redtail.py send -r ./dir --to REMOTE_HOST:47000 --blob
```

Check space before a large run, and compare after unpacking:

```bash
df -h /Volumes/SSD ~
python3.10 redtail.py unpack-blob "/Volumes/SSD/redtail-test/"redtail-blob-*.xbl1 --out ~/restore
diff -rq "/Volumes/SSD" ~/restore/SSD
```

`diff` will list the skipped volume folders and `redtail-test` as missing; any
other line is a real difference. Delete `redtail-test` between runs, or the next
run packs the previous container too.

### Notes

- `-r` with `--blob` stores relative paths in XBL1 names; `unpack-blob`
  recreates the folders and refuses absolute paths, `..` and duplicates.
- `unpack-blob` accepts at most 100,000 entries; drop `--blob` above that.
- `--HUNTSPF`/`--HUNTSPF2` are not applied under `--RS42` and are rejected; use
  `--HUNTSPF3` or `--HUNTSPF4` to compose with RS42.
- A file smaller than `--streams` uses fewer streams; a failed sender stream
  stops the run instead of hanging it.

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
