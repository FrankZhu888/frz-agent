import importlib.util
import os
import tempfile
import unittest


SKILLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "skills")
SCRIPT_PATH = os.path.join(SKILLS_DIR, "general-log-analyzer", "log_preprocess.py")
SPEC = importlib.util.spec_from_file_location("general_log_preprocess", SCRIPT_PATH)
log_preprocess = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(log_preprocess)


class ErrorContextTests(unittest.TestCase):
    def extract(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "application.log")
            with open(path, "w", encoding="utf-8") as log_file:
                log_file.write("\n".join(lines) + "\n")
            return log_preprocess.extract_error_context(path)

    def test_overlapping_errors_are_merged_without_losing_context(self):
        lines = ["line %02d" % number for number in range(1, 21)]
        lines[5] += " ERROR first"
        lines[11] += " ERROR second"

        contexts = self.extract(lines)

        self.assertEqual(1, len(contexts))
        start_line, context = contexts[0]
        self.assertEqual(1, start_line)
        self.assertEqual(lines[:17], context)
        self.assertIn("ERROR first", "\n".join(context))
        self.assertIn("ERROR second", "\n".join(context))

    def test_nonoverlapping_errors_remain_separate(self):
        lines = ["line %02d" % number for number in range(1, 31)]
        lines[5] += " ERROR first"
        lines[24] += " ERROR second"

        contexts = self.extract(lines)

        self.assertEqual(2, len(contexts))
        self.assertEqual((1, lines[:11]), contexts[0])
        self.assertEqual((20, lines[19:30]), contexts[1])


if __name__ == "__main__":
    unittest.main()
