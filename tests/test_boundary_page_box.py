"""Tests for the page-box boundary rule.

Text is a finding only when its bounding box lies outside the page box
(MediaBox / CropBox) by more than the tolerance. Ordinary headers and footers -
including Word's default 0.5 in header and footer - sit inside the page box and
must not be flagged.
"""

import pytest
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from doc_sherlock.detectors.boundary_detector import BoundaryDetector
from doc_sherlock.findings import FindingType


def write_pdf(path, lines):
    """Write a one-page US Letter PDF. lines: (x, y, size, text) in PDF user space."""
    pdf = canvas.Canvas(str(path), pagesize=letter)
    for x, y, size, text in lines:
        pdf.setFont("Helvetica", size)
        pdf.drawString(x, y, text)
    pdf.save()
    return str(path)


def boundary_findings(pdf_path, config=None):
    return [
        f for f in BoundaryDetector(pdf_path, config).detect()
        if f.finding_type == FindingType.OUTSIDE_BOUNDARY
    ]


def test_clean_letter_with_header_and_footer_is_not_flagged(tmp_path):
    pdf_path = write_pdf(tmp_path / "clean_letter.pdf", [
        (72, 760, 10, "ACME Corporation Ltd - 1 High Street, London"),
        (72, 700, 12, "Dear Customer, this is an ordinary business letter."),
        (72, 30, 10, "Page 1 of 1"),
    ])
    assert boundary_findings(pdf_path) == []


def test_word_default_half_inch_header_and_footer_are_not_flagged(tmp_path):
    pdf_path = write_pdf(tmp_path / "word_default.pdf", [
        (72, 756, 11, "Header half an inch from the top of the page"),
        (72, 400, 11, "Body text."),
        (72, 36, 11, "Footer half an inch from the bottom of the page"),
    ])
    assert boundary_findings(pdf_path) == []


def test_text_beyond_the_right_page_edge_is_flagged(tmp_path):
    pdf_path = write_pdf(tmp_path / "off_right.pdf", [
        (72, 700, 12, "This is normal visible text"),
        (622, 650, 12, "This text starts beyond the 612 pt page width"),
    ])
    findings = boundary_findings(pdf_path)
    assert len(findings) == 1
    assert findings[0].metadata["violations"] == ["right"]
    assert findings[0].metadata["outside_points"]["right"] > 1.0


def test_text_below_the_bottom_page_edge_is_flagged(tmp_path):
    pdf_path = write_pdf(tmp_path / "off_bottom.pdf", [
        (72, 700, 12, "This is normal visible text"),
        (100, -20, 12, "This text sits below the bottom of the page"),
    ])
    findings = boundary_findings(pdf_path)
    assert len(findings) == 1
    assert findings[0].metadata["violations"] == ["bottom"]


def test_tolerance_is_configurable(tmp_path):
    pdf_path = write_pdf(tmp_path / "off_right_wide_tolerance.pdf", [
        (622, 650, 12, "This text starts beyond the 612 pt page width"),
    ])
    assert boundary_findings(pdf_path) != []
    assert boundary_findings(pdf_path, {"boundary_tolerance_pt": 400}) == []
