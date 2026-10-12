# Baseline — checkpoint 1

1. Baseline chưa tạo `agent_id`, `run_id` hay lấy danh tính người dùng để kiểm
   quyền. `_naive_loop()` nhận duy nhất `message` và `llm`, sau đó đưa toàn văn
   ticket vào cùng context (`agent/loop.py:27-34`). Ticket vốn là dữ liệu nhưng
   chỉ thị cài trong ticket lại được `find_injection()` diễn giải như lệnh.

2. Không có policy nào kiểm mục đích, quyền hoặc loại dữ liệu trước egress.
   Chính kết quả do LLM trả về quyết định customer cần đọc và URL cần gửi:
   baseline gọi thẳng `read_customer()` rồi `http_post()` tại
   `agent/loop.py:37-44`. Allowlist trong `agent/tools.py:68-84` chỉ giới hạn
   sink ở localhost, không quyết định dữ liệu nào được phép gửi.

3. Body POST được tạo trực tiếp ở `agent/loop.py:44` dưới dạng
   `{"records": collected}`. Sink nhận body tại `sink/sink.py:42-47` và append
   từng request thành một dòng JSON trong `reports/sink.log`; bản chứng cứ cần
   nộp được sao chép sang `reports/attack-before.log`.
