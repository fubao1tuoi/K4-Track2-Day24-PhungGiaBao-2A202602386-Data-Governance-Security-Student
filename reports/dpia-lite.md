# DPIA-lite — checkpoint 5

1. **Loại dữ liệu và phân loại:** ticket support trong `corpus/` là nội dung
   `internal` nhưng không tin cậy vì người gửi có thể cài chỉ thị. Hồ sơ khách
   synthetic trong `data/customers.json` gồm tên, CCCD, số điện thoại, STK,
   email và được xử lý là `restricted`. Lab không dùng PII thật.
2. **Mục đích và principal:** `support_l1` được tìm/tóm tắt ticket cho
   `summarize-tickets` nhưng không được đọc hồ sơ. `dpo` được đọc khách gắn với
   ticket cho `support-reply`. Principal lấy từ fixture và `--as` chỉ mô phỏng,
   không xác thực người đang sử dụng máy.
3. **Luồng dữ liệu:** Run A gọi `search_docs`, phát hiện lure và redact PII trước
   khi đưa tài liệu vào summarizer. Chỉ `list[int]` lấy từ tên file đi sang Run B.
   Run B ánh xạ ticket qua `related_tickets`, kiểm policy rồi mới gọi
   `read_customer`. Yêu cầu egress được kiểm riêng; endpoint thử nghiệm duy nhất
   là `http://127.0.0.1:10024/reconcile`. Ledger chỉ nhận `args_hash`, decision
   và metadata, không nhận hồ sơ thô.
4. **Bằng chứng và giới hạn:** `reports/attack-before.log` chứa bốn POST synthetic;
   `reports/attack-after.log` có kích thước 0 byte. Ledger có `http_post=deny`,
   reason và `on_behalf_of=dpo`, đồng thời `verify()` trả `True`. Tuy nhiên mock
   không đại diện đầy đủ cho model thật; quyền là fixture; regex có thể bỏ sót
   format mới; hash chain local không phát hiện cắt dòng cuối hoặc việc viết lại
   cả chuỗi nếu không có checkpoint tin cậy bên ngoài. Đây không phải DPIA pháp
   lý chính thức hay đánh giá hệ thống production.
