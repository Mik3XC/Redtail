import itertools
import os
import tempfile
import unittest
from pathlib import Path

import redtail as mt


class ReedSolomon42Tests(unittest.TestCase):
    def test_all_single_and_double_erasure_patterns(self):
        patterns = [()] + [(i,) for i in range(6)]
        patterns += list(itertools.combinations(range(6), 2))

        for size in (1, 3, 4, 5, 473, 947, 1420):
            source = os.urandom(size)
            shards = mt.rs42_encode(source)

            for missing in patterns:
                with self.subTest(size=size, missing=missing):
                    received = tuple(i for i in range(6) if i not in missing)
                    chosen, inverse = mt.rs42_decoder(received)
                    selected = [shards[i] for i in chosen]
                    data = b"".join(
                        mt.gf_linear_combine(selected, row) for row in inverse
                    )[:size]
                    self.assertEqual(source, data)


class SpfTests(unittest.TestCase):
    def test_spf_control_arms_follow_gf_relation(self):
        for level in (2, 3, 4):
            packed = mt.pack_spf_control(67_108_864, level)
            vectors = [packed[i * 9 + 1:(i + 1) * 9] for i in range(level)]
            self.assertEqual(vectors, mt.spf_arms(vectors[0], level))


class BlobTests(unittest.TestCase):
    def test_blob_round_trip(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            inputs = root / "inputs"
            outputs = root / "outputs"
            inputs.mkdir()
            expected = {
                "alpha.txt": b"alpha\n",
                "random.dat": os.urandom(4097),
            }
            paths = []
            for name, data in expected.items():
                path = inputs / name
                path.write_bytes(data)
                paths.append(str(path))

            blob = mt.build_blob(paths)
            try:
                unpacked = mt.unpack_blob(blob, outputs)
            finally:
                os.remove(blob)

            self.assertEqual({Path(path).name for path in unpacked}, set(expected))
            for name, data in expected.items():
                self.assertEqual((outputs / name).read_bytes(), data)


class RecursiveInputTests(unittest.TestCase):
    def make_tree(self, root):
        tree = {"photos/a.bin": os.urandom(5000), "photos/2026/empty.txt": b"",
                "photos/2026/deep/one.bin": b"x"}
        for rel, data in tree.items():
            path = root / "src" / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return tree

    def test_directory_needs_recursive_flag(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            self.make_tree(root)
            with self.assertRaises(ValueError):
                mt.expand_inputs([str(root / "src" / "photos")])
            entries = mt.expand_inputs([str(root / "src" / "photos")], recursive=True)
            self.assertEqual(sorted(rel for _, rel in entries),
                             ["photos/2026/deep/one.bin", "photos/2026/empty.txt", "photos/a.bin"])

    def test_nested_blob_round_trip(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            tree = self.make_tree(root)
            blob = mt.build_blob(mt.expand_inputs([str(root / "src" / "photos")], recursive=True))
            try:
                mt.unpack_blob(blob, root / "out")
            finally:
                os.remove(blob)
            for rel, data in tree.items():
                self.assertEqual((root / "out" / rel).read_bytes(), data)

    def test_unpack_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            name = b"../evil.txt"
            blob = root / "evil.xbl1"
            blob.write_bytes(mt.BLOB_HEAD.pack(mt.BLOB_MAGIC, 1) +
                             mt.BLOB_ENTRY.pack(len(name), 1) + name + b"x")
            with self.assertRaises(ValueError):
                mt.unpack_blob(blob, root / "out")
            self.assertFalse((root / "evil.txt").exists())

    def test_local_drop_rs42_two_erasures(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            tree = self.make_tree(root)
            entries = mt.expand_inputs([str(root / "src" / "photos")], recursive=True)
            jobs = [(rel, path, rel) for path, rel in entries]
            placed, failed = mt.local_drop(jobs, root / "ssd", streams=2, rec=0,
                                           rs42=True, drop_shards=(2, 3))
            self.assertEqual(failed, [])
            self.assertEqual(len(placed), len(tree))
            for rel, data in tree.items():
                self.assertEqual((root / "ssd" / rel).read_bytes(), data)
            self.assertFalse((root / "ssd" / ".redtail-staging").exists())


if __name__ == "__main__":
    unittest.main()
