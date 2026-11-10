import os
import asyncio
import json
import re
import time
import traceback
import httpx

import schemas

from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from groq import AsyncGroq
from dotenv import load_dotenv
from db_connection import get_db
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from connection_manager import ConnectionManager
from security import (
    COOKIE, ORIGIN, TTL_MINUTES, decode_session, hash_password,
    issue_token, revoke_session, verify_password,
)

load_dotenv()

http_client = httpx.AsyncClient(verify=False)

app = FastAPI(title='WebSocket seguro — etapa 3')
manager = ConnectionManager()

api_key = os.getenv("GROQ_API_KEY")
if not api_key:
    raise ValueError("A varável da API não existe")

groq_client = AsyncGroq(
    api_key=os.getenv("GROQ_API_KEY"),
    http_client=http_client
)
# APENAS PARA APRENDIZADO: reiniciar apaga tudo.
users_by_name: dict[str, dict] = {}
users_by_id: dict[str, dict] = {}
room_members: dict[str, set[str]] = {'geral': set()}
room_owners: dict[str, str | None] = {'geral': None}
auth_attempts: dict[str, deque[float]] = defaultdict(deque)

class ChatRequest(BaseModel):
    prompt: str

class Credentials(BaseModel):
    name: str = Field(pattern=r'^[a-zA-Z0-9_]{3,24}$')
    email: str = Field(pattern="^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$")
    password: str = Field(min_length=8, max_length=128)


class NewRoom(BaseModel):
    name: str = Field(pattern=r'^[a-z0-9_-]{3,24}$')


class AddMember(BaseModel):
    username: str = Field(pattern=r'^[a-zA-Z0-9_]{3,24}$')


def check_origin(request: Request):
    # Navegadores enviam Origin em POST; clientes CLI podem não enviar.
    origin = request.headers.get('origin')
    if origin is not None and origin != ORIGIN:
        raise HTTPException(status_code=403, detail='Origin não permitida.')


def limit_auth(ip: str):
    now = time.monotonic()
    bucket = auth_attempts[ip]
    while bucket and now - bucket[0] > 60:
        bucket.popleft()
    if len(bucket) >= 8:
        raise HTTPException(status_code=429, detail='Tente novamente em 1 minuto.')
    bucket.append(now)


def get_session(request: Request) -> tuple[dict, str]:
    decoded = decode_session(request.cookies.get(COOKIE))
    if decoded is None:
        raise HTTPException(status_code=401, detail='Login necessário.')
    user_id, jti = decoded
    user = users_by_id.get(user_id)
    if user is None:
        raise HTTPException(status_code=401, detail='Sessão inválida.')
    return user, jti


def current_user(request: Request) -> dict:
    return get_session(request)[0]


@app.get('/')
def homepage():
    html = Path(__file__).with_name('index.html').read_text(encoding='utf-8')
    return HTMLResponse(html)

historico_contexto = []
@app.post("/chat")
async def chat_endpoint(request: ChatRequest):
    historico_contexto.append({"role": "user", "content": request.prompt})

    try:
        completion = await groq_client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=historico_contexto,
            temperature=0.7
        )
        
        historico_contexto.append({"role": "assistant", "content": request.prompt})
                
        return {"response": completion.choices[0].message.content}

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/teste-conexao")
async def testar_conexao(db: AsyncSession = Depends(get_db)):
    result = await db.execute(text("SELECT VERSION()"))
    versao = result.scalar()

    return {
        "status": "Conectado ao MySQL com sucesso!",
        "versao_mysql": versao
    }

@app.post("/register/system", respon)
async def posta_usuario(user: Credentials, request: Request, db: AsyncSession = Depends(get_db)):
    check_origin(request)
    limit_auth(request.client.host if request.client else 'unknown')
    result = await db.execute(select(Usuario).where(Usuario.email == usuario.email))


@app.post('/register', status_code=201)
async def register(data: Credentials, request: Request):
    check_origin(request)
    limit_auth(request.client.host if request.client else 'unknown')
    name = data.username.lower()
    if name in users_by_name:
        raise HTTPException(status_code=409, detail='Usuário já existe.')
    hashed = await asyncio.to_thread(hash_password, data.password)
    if name in users_by_name:
        raise HTTPException(status_code=409, detail='Usuário já existe.')
    user = {'id': uuid4().hex, 'username': name, 'hash': hashed}
    users_by_name[name] = user
    users_by_id[user['id']] = user
    room_members['geral'].add(user['id'])
    return {'message': 'Conta criada. Agora faça login.'}


@app.post('/login')
async def login(data: Credentials, request: Request, response: Response):
    check_origin(request)
    limit_auth(request.client.host if request.client else 'unknown')
    user = users_by_name.get(data.username.lower())
    correct = await asyncio.to_thread(verify_password,
                                      data.password, user['hash'] if user else None)
    if user is None or not correct:
        raise HTTPException(status_code=401, detail='Credenciais inválidas.')
    token = issue_token(user['id'])
    response.set_cookie(
        key=COOKIE, value=token, max_age=TTL_MINUTES * 60,
        httponly=True, secure=ORIGIN.startswith('https://'),
        samesite='strict', path='/',
    )
    return {'username': user['username']}


@app.post('/logout')
async def logout(request: Request, response: Response):
    check_origin(request)
    decoded = decode_session(request.cookies.get(COOKIE))
    if decoded is not None:
        _, jti = decoded
        revoke_session(jti)
        await manager.kick_session(jti)
    response.delete_cookie(COOKIE, path='/', samesite='strict',
                           secure=ORIGIN.startswith('https://'), httponly=True)
    return {'message': 'Sessão encerrada.'}


@app.get('/me')
def me(user: dict = Depends(current_user)):
    return {'id': user['id'], 'username': user['username']}


@app.get('/rooms')
def rooms(user: dict = Depends(current_user)):
    return {'rooms': sorted(name for name, members in room_members.items()
                            if user['id'] in members)}


@app.post('/rooms', status_code=201)
def create_room(data: NewRoom, request: Request,
                user: dict = Depends(current_user)):
    check_origin(request)
    if data.name in room_members:
        raise HTTPException(409, 'Sala já existe.')
    room_members[data.name] = {user['id']}
    room_owners[data.name] = user['id']
    return {'name': data.name}


@app.post('/rooms/{room}/members')
def invite(room: str, data: AddMember, request: Request,
           user: dict = Depends(current_user)):
    check_origin(request)
    if room_owners.get(room) != user['id']:
        raise HTTPException(403, 'Apenas o criador pode convidar.')
    invited = users_by_name.get(data.username.lower())
    if invited is None:
        raise HTTPException(404, 'Usuário não encontrado.')
    room_members[room].add(invited['id'])
    return {'message': f'{invited["username"]} entrou na lista de membros.'}


@app.websocket('/ws')
async def websocket_endpoint(socket: WebSocket):
    # Proteção contra conexões cross-site com cookie automático.
    if socket.headers.get('origin') != ORIGIN:
        await socket.close(code=1008)
        return

    decoded = decode_session(socket.cookies.get(COOKIE))
    if decoded is None:
        await socket.close(code=1008)
        return

    user_id, jti = decoded
    user = users_by_id.get(user_id)
    room = socket.query_params.get('room', '')
    if user is None or user_id not in room_members.get(room, set()):
        await socket.close(code=1008)
        return

    client = await manager.connect(socket, user_id, user['username'], room, jti)
    if client is None:
        return

    timestamps = deque()
    try:
        while True:
            raw = await socket.receive_text()

            # Sessões encerradas/expiradas deixam de poder enviar mensagens.
            if decode_session(socket.cookies.get(COOKIE)) != (user_id, jti):
                await socket.close(code=1008)
                break
            if user_id not in room_members.get(room, set()):
                await socket.close(code=1008)
                break

            now = time.monotonic()
            while timestamps and now - timestamps[0] > 10:
                timestamps.popleft()
            timestamps.append(now)
            if len(timestamps) > 10:
                await socket.close(code=1008, reason='Limite de mensagens')
                break

            if len(raw.encode('utf-8')) > 2048:
                await manager.send(client, {'type': 'error', 'message': 'Mensagem grande demais.'})
                continue
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await manager.send(client, {'type': 'error', 'message': 'JSON inválido.'})
                continue
            if not isinstance(data, dict) or data.get('type') not in ('chat', 'private'):
                await manager.send(client, {'type': 'error', 'message': 'Tipo inválido.'})
                continue
            message_text = data.get('text')
            if not isinstance(message_text, str) or not 1 <= len(message_text.strip()) <= 500:
                await manager.send(client, {'type': 'error', 'message': 'Texto inválido (1–500 caracteres).'})
                continue

            payload = {
                'type': data['type'], 'fromId': client.id,
                'fromName': client.name, 'text': message_text.strip(),
                'sentAt': datetime.now(timezone.utc).isoformat(),
            }
            if data['type'] == 'chat':
                await manager.broadcast(room, payload)
            else:
                target_id = data.get('to')
                target = manager.find(room, target_id) if isinstance(target_id, str) else None
                if target is None or target.id == client.id:
                    await manager.send(client, {'type': 'error', 'message': 'Destinatário indisponível.'})
                    continue
                payload.update({'to': target.id, 'toName': target.name})
                if await manager.send(target, payload):
                    await manager.send(client, payload)
                else:
                    await manager.presence(room)
                    await manager.send(client, {'type': 'error', 'message': 'Destinatário desconectado.'})

    except WebSocketDisconnect:
        pass
    finally:
        if manager.remove(client):
            await manager.presence(room)
