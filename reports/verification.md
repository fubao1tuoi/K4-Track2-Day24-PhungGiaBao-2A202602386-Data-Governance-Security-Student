# Verification — điền trước khi nộp

- OS / Python / Gitleaks version: Windows native; Python `3.11.0`;
  Gitleaks `8.30.1`.
- `python -m pytest tests/ -q --basetemp=.pytest_tmp`: `33 passed`, `0 skipped`
  trong 5.34 giây ở lượt kiểm cuối.
- `pre-commit run --all-files`: `Detect hardcoded secrets...Passed`.
- Ledger verify: `True`; 92 dòng sau các lượt chạy, gồm 4 dòng
  `http_post=deny` thay mặt `dpo`, tất cả có reason.
- Evidence: `reports/attack-before.log` = 1196 byte và chứa POST synthetic;
  `reports/attack-after.log` = 0 byte.
- Các lỗi còn lại: không có lỗi test. Môi trường Python global có conflict
  ngoài phạm vi lab (Airflow thiếu FastAPI; Ultralytics yêu cầu NumPy <2),
  không ảnh hưởng suite này. Windows native chưa phải môi trường được đề bài pilot.

## CP3a — PII gate

- Lệnh: `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp`
- Kết quả: `2 passed`; `gold=118`, `pred=118`, `tp=118`,
  `precision=1.000`, `recall=1.000`.
- Giới hạn: recognizer dùng regex và nhãn ngữ cảnh (`CCCD`, `SĐT`,
  `số điện thoại`, `STK`, `số tài khoản`). Nó không nhận diện tên người,
  không xác thực checksum/tính hợp lệ nghiệp vụ, và có thể bỏ sót cách viết
  hoặc định dạng số không nằm trong các mẫu đã hỗ trợ.

## CP3b/CP3c — Policy và OBO

- `python -m pytest tests/test_policy.py -v --basetemp=.pytest_tmp`:
  `4 passed`.
- `python -m pytest tests/test_obo.py -v --basetemp=.pytest_tmp`:
  `5 passed`.
- Principal trong `data/principals.json` chỉ là fixture mô phỏng quyền;
  `--as` không phải cơ chế xác thực danh tính production.

## CP3d/CP3e — Split, injection containment và ledger

- `python -m pytest tests/test_split.py -v --basetemp=.pytest_tmp`:
  `1 passed`; khách `KH-000777` chỉ xuất hiện trong attacker text không bị đọc,
  trong khi khách gắn với ticket hợp lệ vẫn được đọc.
- `python -m pytest tests/test_injection.py -v --basetemp=.pytest_tmp`:
  `8 passed`, không có SKIP (4 lure × 2 principal).
- `python -m pytest tests/test_ledger.py -v --basetemp=.pytest_tmp`:
  `3 passed`, gồm kiểm tra phát hiện sửa dòng cũ.
- Chạy tay `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"`
  tạo 23 ledger entries. `verify(reports/ledger.jsonl)` trả `True`.
- Ledger có một quyết định `http_post=deny`, `on_behalf_of=dpo`, với reason
  `restricted data is denied in an egress-enabled run`; tham số chỉ được lưu
  dưới dạng `args_hash`, không lưu hồ sơ hoặc PII thô.

## CP4 — Supply chain và secret scanning

- Cài Gitleaks `8.30.1`; `gitleaks version` trả `8.30.1`.
- `gitleaks git --config .gitleaks.toml --redact .`: quét 4 commit, tìm đúng
  1 token giả ở lịch sử và trả exit code 1 như dự kiến.
- `gitleaks dir --config .gitleaks.toml --redact .`: không finding, exit code 0.
- Sinh `requirements.lock` bằng
  `python -m piptools compile --generate-hashes -o requirements.lock requirements.txt`;
  `python -m pip install --require-hashes -r requirements.lock` chạy thành công.
- Tạo hook pin `v8.30.1`; `pre-commit install` thành công và
  `pre-commit run --all-files` pass.
- `python -m pytest tests/test_supply_chain.py -v --basetemp=.pytest_tmp`:
  lần đầu `2 passed, 1 failed` vì incident note còn là template; sau khi ghi
  đúng commit/rule/rotate, chạy lại được `3 passed`.

## CP5 — Prove sau containment

- Reset sink, chạy full suite: `33 passed`, không có skip.
- Reset sink lần nữa, bật sink localhost và chạy
  `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"`.
- `reports/attack-after.log` = 0 byte; `reports/attack-before.log` = 1196 byte.
- `verify(Path("reports/ledger.jsonl"))` trả `True`; ledger hiện có 92 dòng,
  gồm 88 allow và 4 deny. Cả 4 deny là `http_post` thay mặt `dpo` và có reason.
