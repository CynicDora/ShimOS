"""Stdlib unittest substitute; this is explicitly not pytest qualification."""
import json
import os
import subprocess
import sys
import time
import unittest

MODE = sys.argv[1] if len(sys.argv) > 1 else "pass"
sys.argv[:] = [sys.argv[0]]
subprocess.run(["/workloads/bin/probe-static", "identity"], check=True)
print(json.dumps({"event": "UNITTEST_STARTED", "mode": MODE,
                  "pid": os.getpid(), "monotonic_ns": time.monotonic_ns()}), flush=True)


class FixedToolTests(unittest.TestCase):
    def test_fixed_arithmetic(self):
        self.assertEqual(sum(i * i + 17 for i in range(10)), 455)

    def test_selected_fixture(self):
        if MODE == "pass":
            self.assertEqual("tool".upper(), "TOOL")
        elif MODE == "fail":
            self.assertEqual(1, 2, "intentional assertion failure")
        elif MODE == "timeout":
            print("UNITTEST_WAITING", flush=True)
            time.sleep(30)
        elif MODE == "partial":
            os.write(1, b"UNITTEST_PARTIAL_WITHOUT_NEWLINE")
            time.sleep(30)
        elif MODE == "descendants":
            self.assertEqual(subprocess.run(["/workloads/bin/probe-static", "grandchild"]).returncode, 0)
        elif MODE == "orphan":
            child = subprocess.Popen(["/workloads/bin/probe-static", "holdio"])
            self.assertEqual(child.wait(), 0)
            print("UNITTEST_DESCENDANT_STILL_HOLDS_OUTPUT", flush=True)
        else:
            self.fail("unknown fixed unittest mode")


if __name__ == "__main__":
    unittest.main(verbosity=2)
