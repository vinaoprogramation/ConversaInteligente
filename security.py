"""Autenticação do tutorial. Armazenamento provisório em memória."""
import os
from dotenv import load_dotenv
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from jwt import InvalidTokenError

load_dotenv() 

SECRET = os.getenv('JWT_SECRET', '')
if len(SECRET) < 32:
    raise RuntimeError('Configure JWT_SECRET com no mínimo 32 caracteres aleatórios.')

ORIGIN = os.getenv('APP_ORIGIN', 'http://127.0.0.1:8000').rstrip('/')
COOKIE = 'ws_session'
TTL_MINUTES = 30
ISSUER = 'fastapi-ws-training'

hasher = PasswordHasher()
# Executar a verificação mesmo para nomes desconhecidos reduz diferenças de tempo.
DUMMY_HASH = hasher.hash('dummy-password-not-a-real-account')

# jti -> id de usuário. Em produção, usar Redis/DB compartilhado.
sessions: dict[str, str] = {}


def hash_password(password: str) -> str:
    return hasher.hash(password)


def verify_password(password: str, stored_hash: str | None) -> bool:
    try:
        ok = hasher.verify(stored_hash or DUMMY_HASH, password)
        return bool(ok) if stored_hash else False
    except (VerificationError, InvalidHashError):
        return False


def issue_token(user_id: str) -> str:
    jti = secrets.token_urlsafe(24)
    now = datetime.now(timezone.utc)
    payload = {
        'sub': user_id,
        'jti': jti,
        'iss': ISSUER,
        'iat': now,
        'exp': now + timedelta(minutes=TTL_MINUTES),
    }
    token = jwt.encode(payload, SECRET, algorithm='HS256')
    sessions[jti] = user_id
    return token


def decode_session(token: str | None) -> tuple[str, str] | None:
    if not token:
        return None
    try:
        data = jwt.decode(
            token, SECRET, algorithms=['HS256'], issuer=ISSUER,
            options={'require': ['exp', 'sub', 'jti', 'iss']},
        )
    except InvalidTokenError:
        return None
    user_id, jti = data.get('sub'), data.get('jti')
    if not isinstance(user_id, str) or not isinstance(jti, str):
        return None
    if sessions.get(jti) != user_id:
        return None
    return user_id, jti


def revoke_session(jti: str) -> None:
    sessions.pop(jti, None)
