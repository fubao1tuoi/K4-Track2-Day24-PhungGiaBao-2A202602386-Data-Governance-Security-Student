# Secret giả trong lịch sử Git — checkpoint 4

- **Scanner và phiên bản:** Gitleaks `8.30.1`, cài từ release chính thức qua
  package `Gitleaks.Gitleaks` của WinGet.
- **Commit chứa token giả:** `1bdd849922156c868a5ee9293d68f5b72e242d2c`
  (SHA ngắn `1bdd849`). Đây là fixture vô hiệu của lab, không phải credential thật.
- **File, rule và kết quả quét lịch sử:** `lab-fake-secret.txt`, rule
  `lab24-synthetic-token`. Lệnh
  `gitleaks git --config .gitleaks.toml --redact .` quét 4 commit, báo đúng
  1 finding và trả exit code 1 như dự kiến. `--redact` tránh in token đầy đủ.
- **Kết quả quét file hiện tại:**
  `gitleaks dir --config .gitleaks.toml --redact .` quét working tree hiện tại,
  không có finding và trả exit code 0. Không cần thêm allowlist cho `.venv/`.
- **Nếu đây là credential thật:** thu hồi/rotate tại dịch vụ phát hành ngay,
  điều tra log sử dụng trái phép, cập nhật nơi đang dùng credential, rồi xử lý
  các bản sao còn trong lịch sử, cache, artifact CI và clone liên quan.
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:** xoá file ở
  commit mới không làm credential đã lộ trong lịch sử tự mất hiệu lực; pin
  dependency và pre-commit chỉ giảm nguy cơ supply-chain/rò rỉ trong tương lai,
  không thay thế việc revoke/rotate một secret đã bị lộ.
