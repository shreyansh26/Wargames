with open("keygenme_patched", "rb+") as f:
    f.seek(0x28)
    f.write(b'\x00\x00')
    f.seek(0x3a)
    f.write(b'\x00\x00\x00\x00\x00\x00')