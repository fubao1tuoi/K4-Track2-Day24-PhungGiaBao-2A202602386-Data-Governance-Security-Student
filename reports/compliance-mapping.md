# Compliance mapping — checkpoint 5

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| [Luật Bảo vệ dữ liệu cá nhân 91/2025/QH15](https://vanban.chinhphu.vn/?classid=1&docid=214590&pageid=27160&typegroup=) | PII detection/redaction; purpose- and scope-based access; không ghi PII thô vào ledger | `agent/pii.py:58`, `agent/pii.py:98`, `agent/policy.py:61`, `agent/runner.py:118` | Chưa xác minh điều khoản cụ thể từ toàn văn; đây là mapping kỹ thuật học tập, không phải kết luận tuân thủ. Regex không thay thế quy trình quản trị dữ liệu production. |
| [Nghị định 356/2025/NĐ-CP](https://vanban.chinhphu.vn/?classid=1&docid=216387&pageid=27160) | PEP trước tool, audit allow/deny có reason, DPIA-lite mô tả luồng xử lý | `agent/runner.py:93`, `agent/ledger.py:58`, `reports/dpia-lite.md:1` | Đã xác minh số hiệu, tên, ngày hiệu lực trên nguồn Chính phủ; chưa đối chiếu điều khoản cụ thể. Ledger local không phải hệ thống audit production. |
| [Luật Trí tuệ nhân tạo 134/2025/QH15](https://vanban.chinhphu.vn/?classid=1&docid=216334&orggroupid=1&pageid=27160) | Con người đặt policy; agent chạy với principal/scope/TTL và có trace quyết định | `agent/policy.py:61`, `agent/runner.py:93`, `agent/ledger.py:83` | Chưa xác minh điều khoản cụ thể; mock deterministic và `--as` không chứng minh identity assurance hay tuân thủ hệ thống AI thật. |
| [OWASP Agentic Top 10 — ASI01, ASI03, ASI04](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | ASI01: tách untrusted text khỏi private run và deny egress; ASI03: OBO intersection/TTL; ASI04: hash lock, Gitleaks và hook pin | `agent/runner.py:130`, `agent/policy.py:61`, `requirements.lock:1`, `.pre-commit-config.yaml:1`, `reports/secrets-incident.md:1` | Mapping control-to-risk là đánh giá của bài lab, không phải chứng nhận OWASP; chưa có IdP thật, sandbox mạnh hay attestation dependency. |

Các link pháp luật trỏ tới Cổng thông tin điện tử Chính phủ. Không viện dẫn
điều khoản cụ thể vì chưa đối chiếu toàn văn từng điều; mô phỏng kỹ thuật không
tự chứng minh tuân thủ pháp luật.
