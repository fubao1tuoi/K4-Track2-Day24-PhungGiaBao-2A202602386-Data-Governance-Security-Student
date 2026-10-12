"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re
import unicodedata


_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+(?![\w-])",
    re.I,
)
_NUMBER_RE = re.compile(r"(?<!\d)\d{8,16}(?!\d)")
_FORMATTED_PHONE_RE = re.compile(r"(?<!\d)0\d(?:[ .-]?\d){8,9}(?!\d)")


def _plain(text: str) -> str:
    """Normalize labels only; offsets always come from the original text."""
    normalized = unicodedata.normalize("NFKD", text.lower().replace("đ", "d"))
    return "".join(char for char in normalized if not unicodedata.combining(char))


def _add(entities: list[dict], entity_type: str, start: int, end: int) -> None:
    """Add a span unless it overlaps a higher-priority span already found."""
    if any(start < item["end"] and item["start"] < end for item in entities):
        return
    entities.append({"type": entity_type, "start": start, "end": end})


def detect(text: str) -> list[dict]:
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    entities: list[dict] = []
    normalized = _plain(text)

    # Email is structurally unambiguous and gets first priority.
    for match in _EMAIL_RE.finditer(text):
        _add(entities, "EMAIL", match.start(), match.end())

    # Vietnamese numeric identifiers overlap heavily.  Classify them using
    # nearby labels instead of reporting the same digits as several PII types.
    for match in _NUMBER_RE.finditer(text):
        start, end = match.span()
        prefix = normalized[max(0, start - 64):start]
        value = match.group()
        if re.search(r"(?:stk|so tai khoan)\s*[:#-]?\s*$", prefix):
            _add(entities, "VN_BANK_ACCOUNT", start, end)
        elif re.search(r"cccd(?:\s+cua\s+[^:]{0,40})?\s*[:#-]?\s*$", prefix):
            if len(value) == 12:
                _add(entities, "VN_CCCD", start, end)
        elif value.startswith("0") and len(value) in (10, 11) and re.search(
            r"(?:sdt|so dien thoai|dien thoai)(?:\s+[^:]{0,40})?\s*[:#-]?\s*$",
            prefix,
        ):
            _add(entities, "VN_PHONE", start, end)

    # Also support phone numbers containing spaces, dots or hyphens.
    for match in _FORMATTED_PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", match.group())
        if len(digits) not in (10, 11):
            continue
        prefix = normalized[max(0, match.start() - 64):match.start()]
        if re.search(r"(?:sdt|so dien thoai|dien thoai)(?:\s+[^:]{0,40})?\s*[:#-]?\s*$", prefix):
            _add(entities, "VN_PHONE", match.start(), match.end())

    return sorted(entities, key=lambda item: (item["start"], item["end"], item["type"]))


def redact(text: str) -> str:
    redacted = text
    for entity in sorted(detect(text), key=lambda item: item["start"], reverse=True):
        replacement = f"[REDACTED_{entity['type']}]"
        redacted = redacted[:entity["start"]] + replacement + redacted[entity["end"]:]
    return redacted
