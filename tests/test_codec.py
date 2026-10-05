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


if __name__ == "__main__":
    unittest.main()
