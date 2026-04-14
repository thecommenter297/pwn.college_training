# Setup môi trường local để làm challenge trên máy local

* Tìm hiểu cách để dùng lệnh `ssh` đến server, từ đó tạo file key và key.pub
* Cài đặt 1 file template để tải hết các file cần thiết từ server của pwn.college về máy local

**get_pwn.sh**
```shell
#!/bin/bash

# 1. Kiểm tra đầu vào
if [ -z "$1" ]; then
    echo "Sử dụng: ./get_pwn.sh <tên-challenge>"
    echo "Ví dụ: ./get_pwn.sh syscall-shenanigans"
    exit 1
fi

RAW_NAME=$1
KEY_PATH="./key" # File key nằm ở thư mục hiện tại
HOST="hacker@dojo.pwn.college"

# 2. Xử lý đổi tên: syscall-shenanigans -> SyscallShenanigans
FOLDER_NAME=$(echo "$RAW_NAME" | awk -F'-' '{for(i=1;i<=NF;i++) printf "%s%s", toupper(substr($i,1,1)), substr($i,2); print ""}')

# Backup an toàn: Nếu folder name bị rỗng vì lý do nào đó, dùng luôn tên gốc
if [ -z "$FOLDER_NAME" ]; then
    FOLDER_NAME=$RAW_NAME
fi

echo "[+] Đang tạo thư mục: $FOLDER_NAME"
mkdir -p "$FOLDER_NAME"
# Di chuyển vào thư mục vừa tạo. Nếu lỗi thì dừng luôn script!
cd "$FOLDER_NAME" || { echo "[-] Lỗi: Không thể vào thư mục $FOLDER_NAME"; exit 1; }

# 3. Danh sách các file cần "vét" từ server
echo "[+] Đang tải từ server về..."

# Lưu ý: Vì ta đã chui vào trong folder con, đường dẫn tới file key phải lùi lại 1 bậc (../$KEY_PATH)

echo "  -> Tải file challenge..."
scp -i "../$KEY_PATH" "$HOST:/challenge/$RAW_NAME" "./$RAW_NAME"

echo "  -> Tải Libc..."
scp -i "../$KEY_PATH" "$HOST:/lib/x86_64-linux-gnu/libc.so.6" "./libc.so.6"

echo "  -> Tải Loader (ld)..."
scp -i "../$KEY_PATH" "$HOST:/lib64/ld-linux-x86-64.so.2" "./ld.so"

echo "  -> Tải libcapstone.so.5..."
# Đường dẫn ĐÃ ĐƯỢC CẬP NHẬT
scp -i "../$KEY_PATH" "$HOST:/lib/libcapstone.so.5" "./libcapstone.so.5"

# Cấp quyền thực thi
chmod +x "$RAW_NAME"

echo "------------------------------------------------"
echo "[OK] Đã gom toàn bộ vào thư mục: $FOLDER_NAME/"
ls -l
echo "------------------------------------------------"
```
* Lưu lại và cấp quyền execute:
```shell
chmod +x get_pwn.sh
```
* Chạy lệnh để tải các file cần thiết cho challenge về máy local
```shell
./get_pwn.sh <tên_binary_challenge>
```
> Ví dụ:
> ```shell
> ./get_pwn.sh syscall-shenanigans
> ```

* Patch file libcapstone.so.5 và libc đã tải về từ pwn.college
```shell
patchelf --set-interpreter ./ld-linux-x86-64.so.2 ./<tên-binary>

patchelf --set-rpath '$ORIGIN' ./<tên-binary>
```
