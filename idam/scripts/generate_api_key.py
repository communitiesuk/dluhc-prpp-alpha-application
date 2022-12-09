import os
import jwt
import uuid
import sys

# Usage: python generate_api_key.py admin <secret>

READ_ONLY = "R"
READ_WRITE = "RW"

print("Argument List:", str(sys.argv))
print(len(sys.argv))

if len(sys.argv) >= 3:
    key_type = READ_WRITE if str(sys.argv[1]) == "admin" else READ_ONLY
    SECRET = str(sys.argv[2])
else:
    key_type = READ_ONLY
    SECRET = os.getenv("JWT_SECRET_KEY", "")

encoded_jwt = jwt.encode(
    {"uuid": str(uuid.uuid4()), "access_type": key_type}, SECRET, algorithm="HS256"
)

print(encoded_jwt)

try:
    decoded_jwt = jwt.decode(encoded_jwt, SECRET, algorithms=["HS256"])
    print(decoded_jwt)
except Exception:
    print("decode error")
