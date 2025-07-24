from rsasignature.rsa import RSA

rsa = RSA(size=512)
message = "hello"

cipher = rsa.encrypt(message, rsa.public_key)
print("Encrypted:", cipher)

plain = rsa.decrypt(cipher)
print("Decrypted:", rsa.recover_string(plain).decode())

sig = rsa.sign(message)
verified = rsa.verify(sig, rsa.public_key)
print("Signature verified:", rsa.recover_string(verified).decode())
