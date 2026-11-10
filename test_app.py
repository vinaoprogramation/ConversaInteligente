import os
import uuid
from starlette.websockets import WebSocketDisconnect

os.environ.setdefault('JWT_SECRET', 'test-' + 'a' * 60)
os.environ.setdefault('APP_ORIGIN', 'http://127.0.0.1:8000')

from fastapi.testclient import TestClient
from main import app

ORIGIN = 'http://127.0.0.1:8000'


def signup_and_login(client, name):
    password = 'passphrase-123'
    assert client.post('/register', json={'username': name, 'password': password}, headers={'Origin': ORIGIN}).status_code == 201
    login = client.post('/login', json={'username': name, 'password': password}, headers={'Origin': ORIGIN})
    assert login.status_code == 200, login.text
    assert 'httponly' in login.headers['set-cookie'].lower()
    assert client.get('/me').json()['username'] == name


def test_auth_rooms_and_ws():
    a, b = 'ana' + uuid.uuid4().hex[:8], 'bru' + uuid.uuid4().hex[:8]
    private_room = 'proj' + uuid.uuid4().hex[:8]
    with TestClient(app) as client_a, TestClient(app) as client_b:
        # Sem cookie, handshake bloqueado.
        try:
            with client_a.websocket_connect('/ws?room=geral', headers={'Origin': ORIGIN}):
                assert False, 'WS sem autenticação foi permitido'
        except WebSocketDisconnect:
            pass
        signup_and_login(client_a, a)
        signup_and_login(client_b, b)

        # Origem cruzada: conexão rejeitada.
        try:
            with client_a.websocket_connect('/ws?room=geral', headers={'Origin': 'https://evil.example'}):
                assert False, 'WS cross-origin permitido'
        except WebSocketDisconnect:
            pass

        # Sala privada só para convidados
        assert client_a.post('/rooms', json={'name': private_room}, headers={'Origin': ORIGIN}).status_code == 201
        assert client_b.get('/rooms').json()['rooms'] == ['geral']
        try:
            with client_b.websocket_connect(f'/ws?room={private_room}', headers={'Origin': ORIGIN}):
                assert False, 'Acesso indevido a sala privada'
        except WebSocketDisconnect:
            pass
        assert client_b.post(f'/rooms/{private_room}/members', json={'username': a}, headers={'Origin': ORIGIN}).status_code == 403
        assert client_a.post(f'/rooms/{private_room}/members', json={'username': b}, headers={'Origin': ORIGIN}).status_code == 200
        assert private_room in client_b.get('/rooms').json()['rooms']

        with client_a.websocket_connect('/ws?room=geral', headers={'Origin': ORIGIN}) as ws_a:
            welcome_a = ws_a.receive_json()
            presence_a = ws_a.receive_json()
            assert welcome_a['type'] == 'welcome'
            assert presence_a['type'] == 'presence'
            with client_b.websocket_connect('/ws?room=geral', headers={'Origin': ORIGIN}) as ws_b:
                welcome_b = ws_b.receive_json()
                presence_b = ws_b.receive_json()
                assert presence_b['type'] == 'presence'
                assert len(presence_b['users']) == 2
                assert len(ws_a.receive_json()['users']) == 2

                ws_a.send_json({'type': 'chat', 'text': 'Ola, galera'})
                assert ws_a.receive_json()['text'] == 'Ola, galera'
                assert ws_b.receive_json()['text'] == 'Ola, galera'

                ws_a.send_json({'type': 'private', 'text': 'Segredo', 'to': welcome_b['id']})
                assert ws_a.receive_json()['type'] == 'private'
                assert ws_b.receive_json()['text'] == 'Segredo'

                ws_a.send_text('nao e json')
                assert ws_a.receive_json()['type'] == 'error'

                # Logout da sessão B remove conexão e invalida o token.
                assert client_b.post('/logout', headers={'Origin': ORIGIN}).status_code == 200
                assert client_b.get('/me').status_code == 401
                assert len(ws_a.receive_json()['users']) == 1
