# CipherShare — Zero-Trust Secure File Sharing Using Hybrid Cryptography

A cybersecurity mini project demonstrating secure file sharing using **AES-256-GCM**, **RSA-OAEP**, **SHA-256**, per-user authentication, access control, access revocation, and tamper-evident audit logs.

## Features
- Account registration/login with password hashing.
- Each user receives an RSA-2048 key pair.
- Files are encrypted with a fresh AES-256-GCM key before being written to disk.
- AES keys are wrapped with RSA-OAEP (SHA-256).
- Sharing re-wraps the file key to a recipient's public key.
- Every download checks ownership or active share permission.
- Access can be revoked for future downloads.
- Ciphertext SHA-256 verification before decryption.
- Hash-chained audit log with a chain verification page.
- Responsive dark dashboard.

## Stack
Python 3.10+ · Flask · SQLite · `cryptography` · HTML/CSS

> This is an educational mini-project prototype. For production deployment, use a hardened secret-management service, HTTPS, CSRF protection, rate limiting, safer key custody, audited authorization, and a dedicated database. The demo stores each user's private key encrypted at rest with a password-derived key. Do not use a reused or important password in a classroom demo.

## Run locally
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
# Optional: set a strong session secret
# Windows PowerShell: $env:FLASK_SECRET_KEY="replace-with-long-random-secret"
# macOS/Linux: export FLASK_SECRET_KEY="replace-with-long-random-secret"
python app.py
```
Open http://127.0.0.1:5000 and register two accounts to test sharing.

## Demo workflow
1. Register User A and User B in separate sessions/browser profiles.
2. Sign in as User A and upload a small test file.
3. Download/decrypt the file using User A's password.
4. Share the file with User B (the owner must enter their account password to unwrap the AES key).
5. Sign in as User B and decrypt the shared file using User B's password.
6. Try accessing a file as an unrelated account; the request should be denied.
7. Open Audit log and verify the hash chain.

## Security notes / limitations
- A revoked share blocks future server downloads. It cannot erase a copy already downloaded or decrypted by a recipient.
- RSA-2048 is used for demo compatibility; RSA-OAEP protects only the short AES key, never the file itself.
- The file is encrypted server-side in this local prototype. For stronger zero-trust guarantees, implement encryption/decryption fully client-side and keep private keys off the server.
- Audit hash chaining is tamper-evident, not immutable against an attacker who can rewrite the database and recompute the entire chain.
- The app has a 20 MB upload limit.
- Do not expose the Flask development server to the public internet.

## GitHub
Do not commit `data/`, `.venv/`, `__pycache__/`, local databases, or secrets. `.gitignore` is included.

## Project structure
```text
CipherShare/
├── app.py
├── requirements.txt
├── templates/
├── static/
├── data/                 # created at runtime; ignored by Git
├── .gitignore
└── README.md
```
