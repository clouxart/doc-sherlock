"""
Tests for the table detector.
"""

import pytest
from doc_sherlock.detectors.table_detector import TableDetector
from doc_sherlock.findings import FindingType
from .test_base import BaseDetectorTest


class TestTableDetector(BaseDetectorTest):
    """Tests for the table detector."""

    def test_detects_hidden_table_content(self):
        """Test that hidden content in tables is detected."""
        pdf_path = self.get_test_pdf_path("hidden_table_content.pdf")

        if pdf_path is None:
            pytest.skip("hidden_table_content.pdf not available")

        detector = TableDetector(pdf_path)
        findings = detector.detect()

        assert len(findings) > 0, "Should detect hidden table content"

        assert any(
            finding.finding_type == FindingType.HIDDEN_TABLE_CONTENT
            for finding in findings
        ), "Should have HIDDEN_TABLE_CONTENT findings"

    def test_detects_table_with_long_values(self):
        """Test that tables with unusually long cell values are detected."""
        pdf_path = self.get_test_pdf_path("hidden_table_content.pdf")

        if pdf_path is None:
            pytest.skip("hidden_table_content.pdf not available")

        detector = TableDetector(pdf_path)
        findings = detector.detect()

        long_value_findings = [
            f for f in findings
            if f.metadata and f.metadata.get("value_length", 0) > 30
        ]
        assert len(long_value_findings) > 0, "Should detect tables with long cell values"

    def test_detects_tiny_font_in_table_context(self):
        """Test that tiny font text in table context is detected."""
        pdf_path = self.get_test_pdf_path("table_with_tiny_font.pdf")

        if pdf_path is None:
            pytest.skip("table_with_tiny_font.pdf not available")

        detector = TableDetector(pdf_path)
        findings = detector.detect()

        assert len(findings) > 0, "Should detect tiny font in table context"
        assert any(
            "tiny font" in f.description.lower() or
            "table" in f.description.lower()
            for f in findings
        ), "Should detect table-related hidden content"

    def test_normal_pdf_no_findings(self):
        """Test that normal PDFs without hidden table content produce minimal findings."""
        pdf_path = self.get_test_pdf_path("prompt_injection.pdf")

        if pdf_path is None:
            pytest.skip("prompt_injection.pdf not available")

        detector = TableDetector(pdf_path)
        findings = detector.detect()

        hidden_table_findings = [
            f for f in findings
            if f.finding_type == FindingType.HIDDEN_TABLE_CONTENT
        ]
        assert len(hidden_table_findings) == 0, "Normal PDF should not trigger table hidden content alerts"

    def test_table_detector_handles_no_tables(self):
        """Test that detector handles PDFs with no tables gracefully."""
        pdf_path = self.get_test_pdf_path("prompt_injection.pdf")

        if pdf_path is None:
            pytest.skip("prompt_injection.pdf not available")

        detector = TableDetector(pdf_path)
        findings = detector.detect()

        assert isinstance(findings, list), "Should return a list of findings"
