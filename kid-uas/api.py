# File utama API yang menjadi core logic dari layanan keamanan (security service)
# Peran server dijelaskan pada soal
# TIPS: Gunakan file .txt sederhana untuk menyimpan data-data pengguna

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, HTTPException, UploadFile, File
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from typing import Optional, List
import os
from datetime import datetime
from contextlib import contextmanager
from cryptography.fernet import Fernet
from jose import jwt, JWTError
from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import timedelta
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PRIV_KEY_PATH = os.path.join(BASE_DIR, "punkhazard-keys", "priv19.pem")
PUB_KEY_PATH  = os.path.join(BASE_DIR, "punkhazard-keys", "pub19.pem")


app = FastAPI(title="Security Service", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT CONFIG 
SECRET_KEY = "KID-UAS-SECRET-KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security = HTTPBearer()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Kunci AES (contoh sederhana)
AES_KEY = Fernet.generate_key()
cipher = Fernet(AES_KEY)

# Fungsi contoh untuk memeriksa apakah layanan berjalan dengan baik (health check)
@app.get("/health")
async def health_check():
    return {
        "status": "Security Service is running",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/")
async def get_index() -> dict:
	return {
		"message": "Hello world! Please visit http://localhost:8080/docs for API UI."
	}

@app.post("/upload-pdf")
async def upload_pdf(file: UploadFile = File(...)):
    fname = file.filename
    ctype = file.content_type
    
    try:
        contents = await file.read()
        with open("temp.pdf", "wb") as f:
            f.write(contents)
    except Exception as e:
        return {
            "message": e
        }
    
    return {
        "message": "File uploaded!",
        "content-type": ctype
    }
    
# Fungsi API untuk menerima public key dan memastikan keutuhan file public key yang diterima
# TODO:
# Lengkapi fungsi berikut untuk menerima unggahan, memeriksa keutuhan file, lalu
# menyimpan public key milik user siapa
# Tentukan parameters fungsi yang diperlukan untuk kebutuhan ini


@app.post("/login")
async def login(username: str):
    access_token = create_access_token({"sub": username})
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

@app.post("/store")
async def store_pubkey(username: str, file: UploadFile = File(...)):
    msg = None

    os.makedirs("keys", exist_ok=True)
    contents = await file.read()
    filepath = f"keys/{username}.pub"

    try:
        with open(filepath, "wb") as f:
            f.write(contents)
        msg = f"Public key for user '{username}' stored successfully."
    except Exception as e:
        msg = f"Failed to store key: {str(e)}"

    return {
        "message": msg,
        "saved_to": filepath
    }

@app.post("/sign-pdf")
async def sign_pdf(file: UploadFile = File(...)):
    data = await file.read()

    with open(PRIV_KEY_PATH, "rb") as f:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
            serialization.load_pem_private_key(
                f.read(), password=None
            ).private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    signature = private_key.sign(data)

    sig_path = f"signed_{file.filename}.sig"
    with open(sig_path, "wb") as f:
        f.write(signature)

    return {
        "message": "PDF signed",
        "pdf": file.filename,
        "signature_file": sig_path
    }


@app.post("/verify-pdf")
async def verify_pdf(
    pdf: UploadFile = File(...),
    signature: UploadFile = File(...)
):
    pdf_data = await pdf.read()
    sig_data = await signature.read()

    with open(PUB_KEY_PATH, "rb") as f:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            serialization.load_pem_public_key(
                f.read()
            ).public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        )

    try:
        public_key.verify(sig_data, pdf_data)
        return {
            "pdf": pdf.filename,
            "verified": True,
            "detail": "Signature VALID"
        }
    except Exception:
        return {
            "pdf": pdf.filename,
            "verified": False,
            "detail": "Signature INVALID"
        }
    
@app.post("/relay")
async def relay(sender: str, receiver: str, message: str, current_user: str = Depends(get_current_user) ):
    if sender != current_user:
        raise HTTPException(status_code=403, detail="Sender mismatch")
    os.makedirs("inbox", exist_ok=True)

    # ENKRIPSI PESAN
    encrypted_message = cipher.encrypt(message.encode("utf-8"))

    filepath = f"inbox/{receiver}.txt"

    with open(filepath, "ab") as f:
        f.write(b"From " + sender.encode() + b": " + encrypted_message + b"\n")

    return {
        "sender": sender,
        "receiver": receiver,
        "status": "Encrypted message relayed",
        "cipher": "AES (Fernet)",
        "saved_to": filepath
    }
    
# Fungsi API untuk memverifikasi signature yang dibuat oleh seorang pengguna
# TODO:
# Lengkapi fungsi berikut untuk menerima signature, menghitung signature dari "tampered message"
# Lalu kembalikan hasil perhitungan signature ke requester
# Tentukan sendiri parameters fungsi yang diperlukan untuk kebutuhan ini
#kodeku
@app.post("/verify-client")
async def verify(username: str, message: str, signature: UploadFile = File(...)):
    pubkey_path = f"keys/{username}.pub"

    if not os.path.exists(pubkey_path):
        raise HTTPException(status_code=404, detail="Public key not found")

    # Load public key
    with open(pubkey_path, "rb") as f:
        pub_pem = f.read()
    pub_key = serialization.load_pem_public_key(pub_pem)

    # Read signature file
    sig_bytes = await signature.read()

    # Try verifying signature
    try:
        pub_key.verify(sig_bytes, message.encode("utf-8"))
        return {
            "username": username,
            "verified": True,
            "detail": "Signature is VALID"
        }
    except Exception:
        return {
            "username": username,
            "verified": False,
            "detail": "Signature is INVALID"
        }


# Fungsi API untuk relay pesan ke user lain yang terdaftar
# TODO:
# Lengkapi fungsi berikut untuk menerima pesan yang aman ke server, 
# untuk selanjutnya diteruskan ke penerima yang dituju (ditentukan oleh pengirim)
# Tentukan sendiri parameters fungsi yang diperlukan untuk kebutuhan ini

#relay versi ekripsi(nilai tambahan)
@app.get("/inbox/{receiver}")
def read_inbox(receiver: str, current_user: str = Depends(get_current_user)):
    if current_user != receiver:
        raise HTTPException(status_code=403, detail="Access denied")
    
    filepath = f"inbox/{receiver}.txt"
    if not os.path.exists(filepath):
        return {"receiver": receiver, "messages": []}
    
    messages = []
    with open(filepath, "rb") as f:
        lines = f.read().splitlines()  # splitlines() sudah hapus \n
        for line in lines:
            if line.startswith(b"From "):
                parts = line.split(b": ", 1)
                sender = parts[0][5:].decode("utf-8")
                encrypted = parts[1].strip()  # <<< TAMBAHKAN .strip() DI SINI
                try:
                    decrypted = cipher.decrypt(encrypted).decode("utf-8")
                    messages.append({"from": sender, "message": decrypted})
                except Exception as e:
                    messages.append({"from": sender, "message": f"[dekripsi gagal: {str(e)}]"})
    
    return {"receiver": receiver, "messages": messages}