import asyncio
from dataclasses import dataclass, field
from uuid import uuid4

from fastapi import WebSocket, WebSocketDisconnect


@dataclass
class Client:
    id: str
    user_id: str
    name: str
    room: str
    session_id: str
    socket: WebSocket
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class ConnectionManager:
    def __init__(self):
        self.rooms: dict[str, dict[str, Client]] = {}

    async def connect(self, socket: WebSocket, user_id: str,
                      name: str, room: str, session_id: str) -> Client | None:
        if len(self.rooms.get(room, {})) >= 50:
            await socket.close(code=1008)
            return None
        active = sum(
            c.user_id == user_id
            for members in self.rooms.values()
            for c in members.values()
        )
        if active >= 5:
            await socket.close(code=1008)
            return None
        await socket.accept()
        client = Client(uuid4().hex, user_id, name, room, session_id, socket)
        self.rooms.setdefault(room, {})[client.id] = client
        await self.send(client, {'type': 'welcome', 'id': client.id,
                                 'name': name, 'room': room})
        await self.presence(room)
        return client

    def remove(self, client: Client) -> bool:
        members = self.rooms.get(client.room)
        if members is None or members.pop(client.id, None) is None:
            return False
        if not members:
            del self.rooms[client.room]
        return True

    def find(self, room: str, client_id: str) -> Client | None:
        return self.rooms.get(room, {}).get(client_id)

    async def send(self, client: Client, data: dict) -> bool:
        try:
            async with client.lock:
                await client.socket.send_json(data)
            return True
        except (WebSocketDisconnect, RuntimeError, OSError):
            self.remove(client)
            return False

    async def broadcast(self, room: str, data: dict):
        before = len(self.rooms.get(room, {}))
        for client in list(self.rooms.get(room, {}).values()):
            await self.send(client, data)
        if len(self.rooms.get(room, {})) != before and data.get('type') != 'presence':
            await self.presence(room)

    async def presence(self, room: str):
        users = [
            {'id': client.id, 'name': client.name}
            for client in self.rooms.get(room, {}).values()
        ]
        await self.broadcast(room, {'type': 'presence', 'users': users})

    async def kick_session(self, jti: str):
        affected = set()
        clients = [c for members in self.rooms.values()
                   for c in list(members.values()) if c.session_id == jti]
        for client in clients:
            self.remove(client)
            affected.add(client.room)
            try:
                await client.socket.close(code=1008, reason='Sessão encerrada')
            except (WebSocketDisconnect, RuntimeError, OSError):
                pass
        for room in affected:
            await self.presence(room)
