"""Excel writer for audit reports.

The writer intentionally uses only the Python standard library so the CLI can
produce an `.xlsx` artifact without forcing users to install spreadsheet
libraries.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile
from xml.sax.saxutils import escape

from .models import AuditReport

_CellValue = str | int | float | None


def write_excel_report(report: AuditReport, destination: Path) -> Path:
    """Write an audit report as a multi-sheet XLSX file."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    sheets = [
        ("Summary", _summary_rows(report)),
        ("Controls", _control_rows(report)),
        ("Findings", _finding_rows(report)),
        ("Stats", _stats_rows(report)),
    ]

    with ZipFile(destination, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", _content_types(len(sheets)))
        archive.writestr("_rels/.rels", _root_relationships())
        archive.writestr("xl/workbook.xml", _workbook(sheets))
        archive.writestr("xl/_rels/workbook.xml.rels", _workbook_relationships(sheets))
        archive.writestr("xl/styles.xml", _styles())
        for index, (_, rows) in enumerate(sheets, start=1):
            archive.writestr(f"xl/worksheets/sheet{index}.xml", _worksheet(rows))
    return destination


def _summary_rows(report: AuditReport) -> list[list[_CellValue]]:
    failed_controls = sum(1 for control in report.controls if control.status == "failed")
    passed_controls = sum(1 for control in report.controls if control.status == "passed")
    return [
        ["Metric", "Value"],
        ["Repository", report.repository],
        ["Source", report.source],
        ["Score", report.score],
        ["Files scanned", report.stats.files_scanned],
        ["Directories scanned", report.stats.directories_scanned],
        ["Total bytes", report.stats.total_bytes],
        ["Controls passed", passed_controls],
        ["Controls failed", failed_controls],
        ["Findings", len(report.findings)],
    ]


def _control_rows(report: AuditReport) -> list[list[_CellValue]]:
    rows: list[list[_CellValue]] = [["Rule ID", "Category", "Severity", "Control", "Status", "Findings", "Recommendation"]]
    for control in report.controls:
        rows.append(
            [
                control.rule_id,
                control.category,
                control.severity.value,
                control.title,
                control.status,
                control.findings_count,
                control.recommendation,
            ]
        )
    return rows


def _finding_rows(report: AuditReport) -> list[list[_CellValue]]:
    rows: list[list[_CellValue]] = [
        ["Rule ID", "Category", "Severity", "Title", "Path", "Line", "Message", "Recommendation"]
    ]
    for finding in report.findings:
        rows.append(
            [
                finding.rule_id,
                finding.category,
                finding.severity.value,
                finding.title,
                finding.path,
                finding.line,
                finding.message,
                finding.recommendation,
            ]
        )
    return rows


def _stats_rows(report: AuditReport) -> list[list[_CellValue]]:
    rows: list[list[_CellValue]] = [
        ["Metric", "Value"],
        ["Files scanned", report.stats.files_scanned],
        ["Directories scanned", report.stats.directories_scanned],
        ["Total bytes", report.stats.total_bytes],
        ["Skipped paths", len(report.stats.skipped_paths)],
        [],
        ["Extension", "Files"],
    ]
    for extension, count in sorted(report.stats.files_by_extension.items()):
        rows.append([extension, count])
    if report.stats.skipped_paths:
        rows.extend([[], ["Skipped path", "Reason"]])
        for skipped in report.stats.skipped_paths:
            path, _, reason = skipped.partition(":")
            rows.append([path, reason])
    return rows


def _content_types(sheet_count: int) -> str:
    sheet_overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{index}.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        for index in range(1, sheet_count + 1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        f"{sheet_overrides}"
        "</Types>"
    )


def _root_relationships() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        "</Relationships>"
    )


def _workbook(sheets: Sequence[tuple[str, list[list[_CellValue]]]]) -> str:
    sheet_entries = "".join(
        f'<sheet name="{escape(name)}" sheetId="{index}" r:id="rId{index}"/>'
        for index, (name, _) in enumerate(sheets, start=1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<sheets>{sheet_entries}</sheets>"
        "</workbook>"
    )


def _workbook_relationships(sheets: Sequence[tuple[str, list[list[_CellValue]]]]) -> str:
    relationships = "".join(
        f'<Relationship Id="rId{index}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{index}.xml"/>'
        for index in range(1, len(sheets) + 1)
    )
    relationships += (
        f'<Relationship Id="rId{len(sheets) + 1}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f"{relationships}"
        "</Relationships>"
    )


def _styles() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
        '<fills count="1"><fill><patternFill patternType="none"/></fill></fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
        "</styleSheet>"
    )


def _worksheet(rows: Sequence[Sequence[_CellValue]]) -> str:
    row_xml = "".join(_row(row_index, row) for row_index, row in enumerate(rows, start=1))
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f"<sheetData>{row_xml}</sheetData>"
        "</worksheet>"
    )


def _row(row_index: int, row: Sequence[_CellValue]) -> str:
    cells = "".join(_cell(row_index, col_index, value) for col_index, value in enumerate(row, start=1))
    return f'<row r="{row_index}">{cells}</row>'


def _cell(row_index: int, col_index: int, value: _CellValue) -> str:
    if value is None:
        value = ""
    reference = f"{_column_name(col_index)}{row_index}"
    style = ' s="1"' if row_index == 1 else ""
    if isinstance(value, (int, float)):
        return f'<c r="{reference}"{style}><v>{value}</v></c>'
    text = escape(str(value), {'"': "&quot;"})
    return f'<c r="{reference}" t="inlineStr"{style}><is><t>{text}</t></is></c>'


def _column_name(index: int) -> str:
    name = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        name = chr(65 + remainder) + name
    return name
