from rsasignature.rsa import RSA

rsa = RSA(size=2048)
message = "hello"

sig = rsa.sign(message)
verified = rsa.verify(sig, rsa.public_key)
print("Signature verified:", rsa.recover_string(verified).decode())
