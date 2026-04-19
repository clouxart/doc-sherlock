"""
Detector for identifying hidden content in PDF tables.
"""

import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
import pdfplumber

from ..findings import Finding, FindingType, Severity
from .base_detector import BaseDetector

logger = logging.getLogger(__name__)


class TableDetector(BaseDetector):
    """Detector for identifying hidden content in PDF tables."""

    def __init__(self, pdf_path: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(pdf_path, config)
        self._load_config()

    def _load_config(self) -> None:
        """Load configuration with default values."""
        self.min_font_size = self.config.get("min_table_font_size", 4.0)
        self.min_col_width = self.config.get("min_column_width", 5.0)
        self.min_row_height = self.config.get("min_row_height", 3.0)

    def detect(self) -> List[Finding]:
        """
        Run the detector and return any findings.

        Returns:
            List of findings from the detector
        """
        findings = []

        try:
            with pdfplumber.open(self.pdf_path) as pdf:
                for i, page in enumerate(pdf.pages):
                    page_number = i + 1
                    page_width = float(page.width)
                    page_height = float(page.height)

                    tables = page.extract_tables()

                    if tables:
                        logger.info(f"[TableDetector] Page {page_number}: Found {len(tables)} table(s)")

                    for table_idx, table in enumerate(tables):
                        table_findings = self._analyze_table(
                            table, page_number, page_width, page_height, table_idx
                        )
                        findings.extend(table_findings)

                    all_chars = page.chars
                    lines = page.lines

                    hidden_chars = [
                        c for c in all_chars
                        if c.get("size", 0) < self.min_font_size
                        and (self._is_in_table_context(c, lines) or len(lines) >= 4)
                    ]

                    if hidden_chars:
                        text_content = "".join(c.get("text", "") for c in hidden_chars[:200])
                        if text_content.strip():
                            findings.append(
                                Finding(
                                    finding_type=FindingType.HIDDEN_TABLE_CONTENT,
                                    description=f"Text with tiny font ({len(hidden_chars)} chars) found in table context",
                                    severity=Severity.HIGH,
                                    page_number=page_number,
                                    text_content=text_content[:500] if text_content else None,
                                    metadata={
                                        "hidden_char_count": len(hidden_chars),
                                        "table_count": len(tables),
                                    }
                                )
                            )

        except Exception as e:
            logger.error(f"Error in TableDetector: {str(e)}")

        return findings

    def _analyze_table(
        self,
        table: List[List[str]],
        page_number: int,
        page_width: float,
        page_height: float,
        table_idx: int
    ) -> List[Finding]:
        """
        Analyze a table for hidden content.

        Args:
            table: Extracted table data
            page_number: Page number
            page_width: Page width
            page_height: Page height
            table_idx: Table index on page

        Returns:
            List of findings
        """
        findings = []

        if not table:
            return findings

        for row_idx, row in enumerate(table):
            cell_texts = []
            for cell in row:
                cell_str = str(cell) if cell else ""
                cell_texts.append(cell_str)

            combined_text = "\n".join(cell_texts)
            all_lines = combined_text.split("\n")
            non_empty_lines = [lt for lt in all_lines if lt.strip()]
            empty_lines = len(all_lines) - len(non_empty_lines)

            if len(all_lines) >= 5 and empty_lines >= 3:
                findings.append(
                    Finding(
                        finding_type=FindingType.HIDDEN_TABLE_CONTENT,
                        description=f"Table cell contains sparse data with empty/missing cell content",
                        severity=Severity.MEDIUM,
                        page_number=page_number,
                        metadata={
                            "table_index": table_idx,
                            "row_index": row_idx,
                            "total_lines": len(all_lines),
                            "non_empty_lines": len(non_empty_lines),
                        }
                    )
                )

            for col_idx, cell in enumerate(row):
                cell_text = str(cell) if cell else ""
                if cell_text.strip() == "":
                    continue
                if len(cell_text) > 30:
                    findings.append(
                        Finding(
                            finding_type=FindingType.HIDDEN_TABLE_CONTENT,
                            description=f"Table cell contains unusually long value",
                            severity=Severity.MEDIUM,
                            page_number=page_number,
                            text_content=cell_text[:100] if len(cell_text) > 100 else cell_text,
                            metadata={
                                "table_index": table_idx,
                                "row_index": row_idx,
                                "col_index": col_idx,
                                "value_length": len(cell_text),
                            }
                        )
                    )

        return findings

    def _is_in_table_context(self, char: Dict, lines: List[Dict]) -> bool:
        """
        Check if a character is within a table-like structure.

        Args:
            char: Character dictionary
            lines: List of line dictionaries from pdfplumber

        Returns:
            True if character appears to be in a table context
        """
        if not lines:
            return False

        char_top = char.get("top", 0)
        char_bottom = char.get("bottom", 0)
        char_x0 = char.get("x0", 0)
        char_x1 = char.get("x1", 0)

        vertical_lines = 0
        horizontal_lines = 0

        for line in lines:
            if line.get("linedirection") == "v":
                line_x0 = line.get("x0", 0)
                line_x1 = line.get("x1", 0)
                line_top = line.get("top", 0)
                line_bottom = line.get("bottom", 0)

                if (char_x0 >= line_x0 - 5 and char_x1 <= line_x1 + 5 and
                    char_top <= line_bottom and char_bottom >= line_top):
                    vertical_lines += 1

            elif line.get("linedirection") == "h":
                line_top = line.get("top", 0)
                line_bottom = line.get("bottom", 0)
                line_x0 = line.get("x0", 0)
                line_x1 = line.get("x1", 0)

                if (char_top <= line_bottom and char_bottom >= line_top and
                    char_x0 <= line_x1 and char_x1 >= line_x0):
                    horizontal_lines += 1

        return vertical_lines >= 2 or horizontal_lines >= 2
