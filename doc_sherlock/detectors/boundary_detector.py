"""
Detector for identifying text positioned outside the page boundaries.
"""

import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
import pypdf
import pdfplumber

from ..findings import Finding, FindingType, Severity
from .base_detector import BaseDetector

logger = logging.getLogger(__name__)


class BoundaryDetector(BaseDetector):
    """Detector for identifying text positioned outside the physical page box.

    A word is reported only when its bounding box falls outside the page box
    (``page.bbox`` - the CropBox where one is present, otherwise the MediaBox)
    by more than ``boundary_tolerance_pt``. Text inside the page, however close
    to the edge, is a margin, not an anomaly: an ordinary letterhead or a
    Word-default 0.5 in footer must not be reported.
    """

    def __init__(self, pdf_path: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(pdf_path, config)
        self._load_config()

    def _load_config(self) -> None:
        """Load configuration with default values."""
        self.boundary_tolerance_pt = float(self.config.get("boundary_tolerance_pt", 1.0))

    def detect(self) -> List[Finding]:
        """
        Run the detector and return any findings.

        Returns:
            List of findings from the detector
        """
        findings: List[Finding] = []
        tolerance = self.boundary_tolerance_pt

        try:
            with pdfplumber.open(self.pdf_path) as pdf:
                for i, page in enumerate(pdf.pages):
                    page_number = i + 1

                    # page.bbox is the page's own box in pdfplumber's top-down
                    # coordinate space, which is what word coordinates are
                    # relative to. CropBox where present, else MediaBox.
                    page_left, page_top, page_right, page_bottom = (
                        float(value) for value in page.bbox
                    )
                    page_width = float(page.width) or 1.0
                    page_height = float(page.height) or 1.0

                    words = page.extract_words(
                        x_tolerance=3,
                        y_tolerance=3,
                        keep_blank_chars=True,
                        use_text_flow=True,
                    )

                    for word in words:
                        text = word.get("text", "")

                        # Skip empty text
                        if not text.strip():
                            continue

                        x0 = float(word.get("x0", 0.0))
                        x1 = float(word.get("x1", 0.0))
                        y0 = float(word.get("top", 0.0))
                        y1 = float(word.get("bottom", 0.0))

                        # How far the word sticks out of the page box, in points.
                        overflow_pt = {
                            "left": page_left - x0,
                            "right": x1 - page_right,
                            "top": page_top - y0,
                            "bottom": y1 - page_bottom,
                        }
                        violations = [
                            name for name, over in overflow_pt.items() if over > tolerance
                        ]
                        if not violations:
                            continue

                        outside_points = {
                            name: max(over, 0.0) for name, over in overflow_pt.items()
                        }
                        outside_percentages = {
                            "left": outside_points["left"] / page_width,
                            "right": outside_points["right"] / page_width,
                            "top": outside_points["top"] / page_height,
                            "bottom": outside_points["bottom"] / page_height,
                        }
                        max_outside = max(outside_percentages.values())

                        # Severity by how far outside the page the text sits.
                        if max_outside > 0.5:
                            severity = Severity.HIGH
                        elif max_outside > 0.2:
                            severity = Severity.MEDIUM
                        else:
                            severity = Severity.LOW

                        findings.append(
                            Finding(
                                finding_type=FindingType.OUTSIDE_BOUNDARY,
                                description=f"Text outside {', '.join(violations)} page boundary",
                                severity=severity,
                                page_number=page_number,
                                location={
                                    "x0": x0 / page_width,
                                    "y0": y0 / page_height,
                                    "x1": x1 / page_width,
                                    "y1": y1 / page_height,
                                },
                                text_content=text,
                                metadata={
                                    "violations": violations,
                                    "outside_points": outside_points,
                                    "outside_percentages": outside_percentages,
                                    "page_box": {
                                        "x0": page_left,
                                        "top": page_top,
                                        "x1": page_right,
                                        "bottom": page_bottom,
                                    },
                                    "tolerance_pt": tolerance,
                                },
                            )
                        )
        except Exception as e:
            logger.error(f"Error in BoundaryDetector: {str(e)}")

        return findings
