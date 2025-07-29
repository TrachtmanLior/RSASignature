from rsasignature.rsa import RSA

# Create RSA instance with 2048-bit keys
rsa = RSA(size=2048)

# Message to sign
message = "Hello, World!"

# Sign the message (uses SHA-256 by default)
signature = rsa.sign(message)

# Verify the signature
is_valid = rsa.verify(signature, rsa.public_key, message)

print(f"Message: {message}")
print(f"Signature valid: {is_valid}")
print(f"Signature (hex): {hex(signature)[:64]}...")