"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


BASE_DIR = Path(__file__).resolve().parent.parent
CUSTOMERS_FILE = BASE_DIR / "data" / "customers.json"
AGENT_ID = "lab24-agent"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(timestamp: datetime) -> str:
    return timestamp.isoformat().replace("+00:00", "Z")


def _args_hash(arguments: object) -> str:
    encoded = json.dumps(arguments, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _authorize_and_log(
    *, ledger_path: Path, run_id: str, tool: str, arguments: object,
    classification: str, purpose: str, principal_id: str,
    agent_scopes: tuple[str, ...], parent_scopes: tuple[str, ...],
    delegation_depth: int, egress_enabled: bool, expires_at: str,
) -> bool:
    context = policy.PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=f"{AGENT_ID}/{run_id}",
        delegation_depth=delegation_depth,
        egress_enabled=egress_enabled,
        principal_id=principal_id,
        requested_tool=tool,
        agent_scopes=agent_scopes,
        parent_scopes=parent_scopes,
        expires_at=expires_at,
    )
    allowed, reason = policy.check(context)
    ledger.append(
        {
            "ts": _iso(_utc_now()),
            "agent_id": AGENT_ID,
            "run_id": run_id,
            "tool": tool,
            "args_hash": _args_hash(arguments),
            "classification": classification,
            "decision": "allow" if allowed else "deny",
            "reason": reason,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        },
        ledger_path,
    )
    return allowed


def _ticket_ids(docs: list[dict]) -> list[int]:
    """Derive typed IDs only from trusted filenames, never document text."""
    result: set[int] = set()
    for doc in docs:
        match = re.fullmatch(r"ticket-(\d+)(?:[a-z]+)?\.md", str(doc.get("id", "")), re.I)
        if match:
            result.add(int(match.group(1)))
    return sorted(result)


def _customers_for_tickets(ticket_ids: list[int]) -> list[str]:
    records = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    wanted = set(ticket_ids)
    return sorted({
        str(record["customer_id"])
        for record in records
        if wanted.intersection(record.get("related_tickets", []))
    })


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    expires_at = _iso(_utc_now() + timedelta(minutes=5))
    invocation = uuid.uuid4().hex
    run_a = f"{invocation}-run-a"
    run_b = f"{invocation}-run-b"

    # Run A owns untrusted content but has neither private-store nor egress scope.
    search_allowed = _authorize_and_log(
        ledger_path=ledger_path,
        run_id=run_a,
        tool="search_docs",
        arguments={"query": message},
        classification="internal",
        purpose="summarize-tickets",
        principal_id=principal_id,
        agent_scopes=("search_docs",),
        parent_scopes=(),
        delegation_depth=0,
        egress_enabled=False,
        expires_at=expires_at,
    )
    docs = tools.search_docs(message) if search_allowed else []
    ticket_ids = _ticket_ids(docs)

    # Detection is observability only.  No customer ID or free text returned
    # by the model crosses into Run B.
    combined_text = "\n\n".join(str(doc.get("text", "")) for doc in docs)
    injected = llm.find_injection(combined_text) if combined_text else None

    # Run B receives only typed ticket IDs and maps them through trusted
    # related_tickets metadata.  Delegation cannot exceed the principal's
    # parent scope.
    principal_tools = {
        "support_l1": ("search_docs",),
        "billing": ("search_docs", "read_customer"),
        "dpo": ("search_docs", "read_customer"),
    }.get(principal_id, ())
    for customer_id in _customers_for_tickets(ticket_ids):
        read_allowed = _authorize_and_log(
            ledger_path=ledger_path,
            run_id=run_b,
            tool="read_customer",
            arguments={"customer_id": customer_id},
            classification="restricted",
            purpose="support-reply",
            principal_id=principal_id,
            agent_scopes=("read_customer",),
            parent_scopes=principal_tools,
            delegation_depth=1,
            egress_enabled=False,
            expires_at=expires_at,
        )
        if read_allowed:
            tools.read_customer(customer_id)

    # A detected lure causes an attempted policy decision, never a direct
    # network call.  Restricted + egress is denied even for DPO.
    if injected is not None:
        _authorize_and_log(
            ledger_path=ledger_path,
            run_id=run_b,
            tool="http_post",
            arguments={"url": injected.target_url, "ticket_ids": ticket_ids},
            classification="restricted",
            purpose="support-reply",
            principal_id=principal_id,
            agent_scopes=("http_post",),
            parent_scopes=principal_tools,
            delegation_depth=1,
            egress_enabled=True,
            expires_at=expires_at,
        )

    # The summarizer receives the same document identities but never raw PII.
    # Injection detection above stays inside Run A; only typed ticket IDs cross
    # into Run B.
    sanitized_docs = [
        {**doc, "text": pii.redact(str(doc.get("text", "")))}
        for doc in docs
    ]
    return llm.summarize(sanitized_docs)
