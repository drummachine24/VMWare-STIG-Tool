import json
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

PROFILE_SUMMARY_RE = re.compile(
    r"Profile Summary:\s*(\d+)\s*successful controls,\s*"
    r"(\d+)\s*control failures,\s*"
    r"(\d+)\s*controls not reviewed,\s*"
    r"(\d+)\s*controls not applicable,\s*"
    r"(\d+)\s*controls have error",
    re.IGNORECASE,
)


@dataclass
class StigCounts:
    nf: int = 0
    nr: int = 0
    na: int = 0
    open: int = 0

    def as_dict(self) -> dict:
        return {"nf": self.nf, "nr": self.nr, "na": self.na, "open": self.open}


@dataclass
class ChecklistItem:
    rule_id: str
    rule_title: str
    severity: str
    stig_title: str
    status: str  # NF, NR, NA, O
    check_content: str
    fix_text: str
    finding_details: str
    control_id: str = ""
    remediation_script: str = ""
    remediation_source: str = ""


@dataclass
class ParsedScanResult:
    counts: StigCounts
    items: list[ChecklistItem] = field(default_factory=list)
    summary: str = ""


def _local_tag(tag: str) -> str:
    return tag.split("}")[-1] if "}" in tag else tag


def parse_profile_summary(text: str) -> StigCounts | None:
    match = PROFILE_SUMMARY_RE.search(text)
    if not match:
        return None
    nf, open_count, nr, na, errors = (int(g) for g in match.groups())
    return StigCounts(nf=nf, nr=nr, na=na, open=open_count + errors)


def _normalize_stig_status(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    compact = re.sub(r"[\s_-]+", "", s.lower())
    exact = {
        "passed": "NF",
        "pass": "NF",
        "notafinding": "NF",
        "notafindingwithfindingdetailspassed": "NF",
        "failed": "O",
        "fail": "O",
        "failure": "O",
        "error": "O",
        "open": "O",
        "skipped": "NR",
        "notreviewed": "NR",
        "notreviewedwithfindingdetailsskipped": "NR",
        "notapplicable": "NA",
        "notapplicablewithfindingdetailsskipped": "NA",
    }
    if compact in exact:
        return exact[compact]
    lower = s.lower()
    if "not applicable" in lower or lower in ("n/a", "na"):
        return "NA"
    if "not reviewed" in lower or lower in ("n/r", "nr"):
        return "NR"
    if "not a finding" in lower or "notafinding" in compact:
        return "NF"
    if "fail" in lower or lower == "open":
        return "O"
    if "pass" in lower:
        return "NF"
    return ""


def _ckl_status_to_code(status: str) -> str:
    code = _normalize_stig_status(status)
    if code:
        return code
    s = (status or "").strip()
    legacy = {
        "NotAFinding": "NF",
        "Not_A_Finding": "NF",
        "Open": "O",
        "Not_Reviewed": "NR",
        "Not_Applicable": "NA",
        "NotApplicable": "NA",
    }
    return legacy.get(s, "NR")


def _inspec_control_status(control: dict) -> str:
    for key in ("status", "descriptive_status", "outcome"):
        val = control.get(key)
        if val:
            code = _normalize_stig_status(str(val))
            if code:
                return code

    results = control.get("results") or []
    statuses: set[str] = set()
    for result in results:
        for key in ("status", "descriptive_status", "outcome"):
            if result.get(key):
                code = _normalize_stig_status(str(result[key]))
                if code:
                    statuses.add(code)

    if "O" in statuses:
        return "O"
    if statuses == {"NA"}:
        return "NA"
    if "NR" in statuses and "NF" not in statuses:
        return "NR"
    if "NF" in statuses:
        return "NF"
    if results:
        # InSpec ran tests but omitted status on passed controls
        return "NF"
    return ""


def _strip_markup(text: str) -> str:
    if not text:
        return ""
    cleaned = re.sub(r"<[^>]+>", " ", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def _counts_from_items(items: list[ChecklistItem]) -> StigCounts:
    counts = StigCounts()
    for item in items:
        if item.status == "NF":
            counts.nf += 1
        elif item.status == "O":
            counts.open += 1
        elif item.status == "NA":
            counts.na += 1
        else:
            counts.nr += 1
    return counts


def _summary_text(counts: StigCounts) -> str:
    return f"{counts.nf} NF / {counts.open} Open / {counts.nr} NR / {counts.na} NA"


def parse_inspec_json(path: Path) -> ParsedScanResult:
    counts = StigCounts()
    items: list[ChecklistItem] = []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not parse InSpec JSON %s: %s", path, exc)
        return ParsedScanResult(counts=counts, summary=str(exc))

    profiles = data.get("profiles") or []
    if isinstance(data.get("controls"), list) and not profiles:
        profiles = [{"name": data.get("name", "Profile"), "controls": data["controls"]}]

    for profile in profiles:
        profile_name = profile.get("name") or profile.get("title") or "Profile"
        stats = (profile.get("statistics") or {}).get("controls") or {}
        if stats:
            counts.nf += int(stats.get("passed") or stats.get("successful") or 0)
            counts.open += int(stats.get("failed") or 0)
            counts.nr += int(stats.get("skipped") or stats.get("not_reviewed") or 0)
            counts.na += int(stats.get("not_applicable") or 0)
            counts.open += int(stats.get("error") or 0)

        for control in profile.get("controls") or []:
            rule_id = str(control.get("id") or control.get("title") or "unknown")
            tags = control.get("tags") or {}
            gid = str(tags.get("gid") or tags.get("vulnid") or rule_id)
            status = _inspec_control_status(control) or "NF"
            desc = _strip_markup(str(control.get("desc") or ""))
            results = control.get("results") or []
            messages = [
                str(r.get("message") or r.get("code_desc") or "").strip()
                for r in results
                if r.get("message") or r.get("code_desc")
            ]
            finding = "\n".join(m for m in messages if m)

            items.append(
                ChecklistItem(
                    rule_id=gid,
                    control_id=rule_id,
                    rule_title=str(control.get("title") or rule_id),
                    severity=str(tags.get("severity") or tags.get("ccis") or "unknown"),
                    stig_title=profile_name,
                    status=status,
                    check_content=desc,
                    fix_text=desc,
                    finding_details=finding,
                )
            )

    if items and not any([counts.nf, counts.nr, counts.na, counts.open]):
        counts = _counts_from_items(items)

    return ParsedScanResult(counts=counts, items=items, summary=_summary_text(counts))


def _vuln_data_pairs(vuln: ET.Element) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for node in vuln.iter():
        if _local_tag(node.tag) != "STIG_DATA":
            continue
        attr_name = ""
        attr_value = ""
        for child in node:
            tag = _local_tag(child.tag)
            text = (child.text or "").strip()
            if tag == "VULN_ATTRIBUTE":
                attr_name = text
            elif tag == "ATTRIBUTE_DATA":
                attr_value = text
        if attr_name:
            pairs[attr_name] = attr_value
    return pairs


def _vuln_field(vuln: ET.Element, attribute: str) -> str:
    pairs = _vuln_data_pairs(vuln)
    for key, value in pairs.items():
        if key.lower() == attribute.lower():
            return value

    for node in vuln.iter():
        tag = _local_tag(node.tag)
        if tag.lower() == attribute.lower() and (node.text or "").strip():
            return node.text.strip()

    for key, value in vuln.attrib.items():
        if _local_tag(key).lower() == attribute.lower() and value:
            return value.strip()

    return ""


def parse_ckl(path: Path) -> ParsedScanResult:
    counts = StigCounts()
    items: list[ChecklistItem] = []

    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
        root = ET.fromstring(raw)
    except (OSError, ET.ParseError) as exc:
        logger.warning("Could not parse CKL %s: %s", path, exc)
        return ParsedScanResult(counts=counts, summary=str(exc))

    for node in root.iter():
        if _local_tag(node.tag).lower() != "istig":
            continue

        stig_title = ""
        for child in node.iter():
            if _local_tag(child.tag) != "SI_DATA":
                continue
            name = ""
            value = ""
            for part in child:
                tag = _local_tag(part.tag)
                text = (part.text or "").strip()
                if tag in ("SID_NAME", "VULN_ATTRIBUTE"):
                    name = text
                elif tag in ("SID_DATA", "ATTRIBUTE_DATA"):
                    value = text
            if name.lower() == "title" and value:
                stig_title = value

        for vuln in node.iter():
            if _local_tag(vuln.tag).lower() != "vuln":
                continue
            if vuln is node:
                continue

            status_raw = _vuln_field(vuln, "Status")
            status = _ckl_status_to_code(status_raw)
            if status == "NF":
                counts.nf += 1
            elif status == "O":
                counts.open += 1
            elif status == "NA":
                counts.na += 1
            else:
                counts.nr += 1

            items.append(
                ChecklistItem(
                    rule_id=_vuln_field(vuln, "Rule_ID") or _vuln_field(vuln, "Vuln_Num"),
                    rule_title=_vuln_field(vuln, "Rule_Title"),
                    severity=_vuln_field(vuln, "Severity"),
                    stig_title=stig_title or _vuln_field(vuln, "Rule_Ver"),
                    status=status,
                    check_content=_vuln_field(vuln, "Check_Content"),
                    fix_text=_vuln_field(vuln, "Fix_Text"),
                    finding_details=_vuln_field(vuln, "Finding_Details"),
                    control_id=_vuln_field(vuln, "Group_Title") or _vuln_field(vuln, "Rule_ID"),
                )
            )

    if not items:
        logger.warning("CKL parsed but no VULN entries found in %s", path)

    return ParsedScanResult(counts=counts, items=items, summary=_summary_text(counts))


def parse_scan_artifact(
    json_path: Path | None,
    ckl_path: Path | None,
    stdout: str = "",
) -> ParsedScanResult:
    """Prefer CKL for checklist detail and counts; fall back to JSON then stdout."""
    parsed_ckl = parse_ckl(ckl_path) if ckl_path and ckl_path.exists() else None
    parsed_json = parse_inspec_json(json_path) if json_path and json_path.exists() else None
    summary_counts = parse_profile_summary(stdout)

    if parsed_ckl and parsed_ckl.items:
        counts = parsed_ckl.counts
        if summary_counts and counts.nf == 0 and counts.open == 0 and summary_counts.nf > 0:
            counts = summary_counts
        parsed_ckl.counts = counts
        parsed_ckl.summary = _summary_text(counts)
        return parsed_ckl

    if parsed_json and parsed_json.items:
        counts = parsed_json.counts
        if summary_counts and counts.nf == 0 and counts.open == 0 and summary_counts.nf > 0:
            counts = summary_counts
        parsed_json.counts = counts
        parsed_json.summary = _summary_text(counts)
        return parsed_json

    if summary_counts:
        return ParsedScanResult(
            counts=summary_counts,
            items=[],
            summary=_summary_text(summary_counts),
        )

    return ParsedScanResult(counts=StigCounts(), items=[], summary="")
