import importlib.util
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock


SKILLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "skills")
SCRIPT_PATH = os.path.join(
    SKILLS_DIR, "k8s-analyzer", "scripts", "k8s_log_preprocess.py")
SPEC = importlib.util.spec_from_file_location("k8s_log_preprocess", SCRIPT_PATH)
k8s_log_preprocess = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(k8s_log_preprocess)


class AnalyzerTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def path(self, name):
        return os.path.join(self.tmpdir.name, name)

    def write_log(self, name, content):
        path = self.path(name)
        with open(path, "w", encoding="utf-8") as log_file:
            log_file.write(content)
        return path

    def add_tar_file(self, archive, name, content=b"log\n", member_type=None):
        member = tarfile.TarInfo(name)
        if member_type is None:
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        else:
            member.type = member_type
            member.linkname = "target"
            archive.addfile(member)


class ArchiveSafetyTests(AnalyzerTestCase):
    def test_normal_tar_and_zip_logs_are_processed(self):
        content = b"2024-01-02T03:04:05 ERROR connection refused\n"
        tar_path = self.path("normal.tar")
        with tarfile.open(tar_path, "w") as archive:
            self.add_tar_file(archive, "logs/kubelet.log", content)
        zip_path = self.path("normal.zip")
        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.writestr("logs/kubelet.log", content)

        for archive_path in (tar_path, zip_path):
            with self.subTest(archive=os.path.basename(archive_path)):
                analyzer = k8s_log_preprocess.LogAnalyzer()
                analyzer.process_path(archive_path)
                self.assertEqual(1, analyzer.error_counts["kubelet"])
                self.assertEqual(1, analyzer.total_lines)

    def test_tar_rejects_absolute_and_parent_paths(self):
        unsafe_names = ("../escape.log", "/absolute.log", "..\\escape.log", "C:\\absolute.log")
        for index, name in enumerate(unsafe_names):
            with self.subTest(name=name):
                tar_path = self.path("unsafe-path-%d.tar" % index)
                with tarfile.open(tar_path, "w") as archive:
                    self.add_tar_file(archive, name)
                analyzer = k8s_log_preprocess.LogAnalyzer()
                with self.assertRaisesRegex(ValueError, "Unsafe archive member path"):
                    analyzer.process_tar(tar_path)
                self.assertFalse(os.path.exists(self.path("escape.log")))

    def test_tar_rejects_links_and_devices(self):
        member_types = (
            tarfile.SYMTYPE,
            tarfile.LNKTYPE,
            tarfile.CHRTYPE,
            tarfile.BLKTYPE,
        )
        for index, member_type in enumerate(member_types):
            with self.subTest(member_type=member_type):
                tar_path = self.path("unsafe-type-%d.tar" % index)
                with tarfile.open(tar_path, "w") as archive:
                    self.add_tar_file(archive, "unsafe", member_type=member_type)
                analyzer = k8s_log_preprocess.LogAnalyzer()
                with self.assertRaisesRegex(ValueError, "Unsupported archive member type"):
                    analyzer.process_tar(tar_path)

    def test_tar_member_count_limit(self):
        tar_path = self.path("too-many-members.tar")
        with tarfile.open(tar_path, "w") as archive:
            self.add_tar_file(archive, "one.log", b"one")
            self.add_tar_file(archive, "two.log", b"two")

        analyzer = k8s_log_preprocess.LogAnalyzer()
        with mock.patch.object(k8s_log_preprocess, "MAX_ARCHIVE_MEMBERS", 1):
            with self.assertRaisesRegex(ValueError, "too many members"):
                analyzer.process_tar(tar_path)

    def test_tar_total_expanded_size_limit(self):
        tar_path = self.path("too-large.tar")
        with tarfile.open(tar_path, "w") as archive:
            self.add_tar_file(archive, "one.log", b"1234")
            self.add_tar_file(archive, "two.log", b"5678")

        analyzer = k8s_log_preprocess.LogAnalyzer()
        with mock.patch.object(k8s_log_preprocess, "MAX_ARCHIVE_TOTAL_SIZE", 4):
            with self.assertRaisesRegex(ValueError, "expanded size exceeds limit"):
                analyzer.process_tar(tar_path)


class InputAndChronologyTests(AnalyzerTestCase):
    def test_missing_input_exits_nonzero_without_report(self):
        missing_path = self.path("missing")
        output_path = self.path("report.md")
        result = subprocess.run(
            [sys.executable, "-I", SCRIPT_PATH, missing_path, output_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("Error:", result.stderr)
        self.assertFalse(os.path.exists(output_path))
        self.assertNotIn("集群状态基本正常", result.stdout)

    def test_first_error_is_chronological_for_every_timestamp_format(self):
        cases = (
            (
                "iso",
                "2024-02-03T10:00:00.000002 ERROR connection refused later\n",
                "2024-02-03 10:00:00.000001 ERROR connection refused earliest\n",
                "2024-02-03 10:00:00.000001",
            ),
            (
                "syslog",
                "Jan  2 10:00:02 ERROR connection refused later\n",
                "Jan  2 10:00:01 ERROR connection refused earliest\n",
                "Jan  2 10:00:01",
            ),
            (
                "time-only",
                "10:00:02.000002 ERROR connection refused later\n",
                "10:00:01.000001 ERROR connection refused earliest\n",
                "10:00:01.000001",
            ),
        )
        for name, later, earliest, expected_time in cases:
            with self.subTest(format=name):
                later_path = self.write_log(name + "-b-kubelet.log", later)
                earliest_path = self.write_log(name + "-a-kubelet.log", earliest)
                analyzer = k8s_log_preprocess.LogAnalyzer()
                analyzer.process_file(later_path)
                analyzer.process_file(earliest_path)

                self.assertEqual(expected_time, analyzer.first_error_time)
                self.assertEqual(earliest_path, analyzer._first_error_entry["filepath"])
                self.assertIn("earliest", analyzer.first_error_msg)

    def test_equal_timestamps_use_path_and_line_as_deterministic_tiebreakers(self):
        timestamp = "2024-01-01T00:00:00"
        path_b = self.write_log("b-kubelet.log", timestamp + " ERROR connection refused b\n")
        path_a = self.write_log("a-kubelet.log", timestamp + " ERROR connection refused a\n")
        analyzer = k8s_log_preprocess.LogAnalyzer()
        analyzer.process_file(path_b)
        analyzer.process_file(path_a)

        self.assertEqual(path_a, analyzer._first_error_entry["filepath"])

    def test_timestamp_less_error_is_not_reported_as_healthy(self):
        path = self.write_log("kubelet.log", "ERROR connection refused without timestamp\n")
        analyzer = k8s_log_preprocess.LogAnalyzer()
        analyzer.process_file(path)

        report = analyzer.generate_report()
        self.assertIn("connection refused without timestamp", report)
        self.assertIn("日志未提供可比较的时间戳", report)
        self.assertNotIn("集群状态基本正常", report)


class BoundedSampleTests(AnalyzerTestCase):
    def test_samples_are_bounded_and_report_counts_remain_exact(self):
        analyzer = k8s_log_preprocess.LogAnalyzer()
        with mock.patch.object(k8s_log_preprocess, "MAX_SAMPLES_PER_COMPONENT", 3):
            for number in range(15):
                analyzer.process_line(
                    "2024-01-01T00:00:%02d ERROR connection refused %d" % (number, number),
                    "kubelet",
                    "kubelet.log",
                    number + 1,
                )
            for number in range(12):
                analyzer.process_line(
                    "2024-01-01T00:01:%02d WARNING warning %d" % (number, number),
                    "kubelet",
                    "kubelet.log",
                    number + 16,
                )

        self.assertEqual(3, len(analyzer.errors["kubelet"]))
        self.assertEqual(3, len(analyzer.warnings["kubelet"]))
        self.assertEqual(15, analyzer.error_counts["kubelet"])
        self.assertEqual(12, analyzer.warning_counts["kubelet"])
        report = analyzer.generate_report()
        self.assertIn("**发现ERROR级错误**: 15 条", report)
        self.assertIn("**发现WARNING级告警**: 12 条", report)
        self.assertIn("kubelet 组件（15条错误）", report)
        for section in ("### 1. 根因概览", "### 2. 组件错误详情", "### 3. 警告信息", "### 5. 验证方法"):
            self.assertIn(section, report)


if __name__ == "__main__":
    unittest.main()
