# File dari sisi client 
# Lengkapi file ini dengan proses-proses pembuatan private, public key, pembuatan pesan rahasia
# TIPS: Untuk private, public key bisa dibuat di sini lalu disimpan dalam file
# sebelum mengakses laman Swagger API

from cryptography.hazmat.primitives.asymmetric import ec, padding,ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

print("Mulai generate key & signature untuk ayu, putri, jati...\n")

# --- Ayu ---
priv_ayu = ed25519.Ed25519PrivateKey.generate()
pub_ayu = priv_ayu.public_key()

# Simpan public key ayu (untuk upload ke server /store)
with open("ayu.pub", "wb") as f:
    f.write(
        pub_ayu.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

# Pesan dari ayu
message_ayu = "Hallo dari ayu"
message_bytes_ayu = message_ayu.encode("utf-8")

# Tanda tangan pesan ayu
signature_ayu = priv_ayu.sign(message_bytes_ayu)

# Simpan signature ayu (untuk verifikasi /verify-client)
with open("sig_ayu.bin", "wb") as f:
    f.write(signature_ayu)

print(f"Pesan ayu: '{message_ayu}'")
print("→ ayu.pub & sig_ayu.bin siap\n")

# --- Putri ---
priv_putri = ed25519.Ed25519PrivateKey.generate()
pub_putri = priv_putri.public_key()

with open("putri.pub", "wb") as f:
    f.write(
        pub_putri.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

message_putri = "Hallo dari putri"
message_bytes_putri = message_putri.encode("utf-8")

signature_putri = priv_putri.sign(message_bytes_putri)

with open("sig_putri.bin", "wb") as f:
    f.write(signature_putri)

print(f"Pesan putri: '{message_putri}'")
print("→ putri.pub & sig_putri.bin siap\n")

# --- Jati ---
priv_jati = ed25519.Ed25519PrivateKey.generate()
pub_jati = priv_jati.public_key()

with open("jati.pub", "wb") as f:
    f.write(
        pub_jati.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

message_jati = "one piece is real"
message_bytes_jati = message_jati.encode("utf-8")

signature_jati = priv_jati.sign(message_bytes_jati)

with open("sig_jati.bin", "wb") as f:
    f.write(signature_jati)

print(f"Pesan jati: '{message_jati}'")
print("→ jati.pub & sig_jati.bin siap\n")
