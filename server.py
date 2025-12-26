#!/usr/bin/env python3
"""
SERVIDOR DE SEÑALIZACIÓN WEBRTC OPTIMIZADO
"""

import asyncio
import websockets
import json
from aiohttp import web
import logging
import os
from uuid import uuid4
import hashlib
import base64
import sqlite3
from pathlib import Path
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, db_path='webrtc.db'):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    avatar_url TEXT,
                    is_online BOOLEAN DEFAULT 0,
                    status TEXT DEFAULT 'disponible',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            conn.commit()

    def hash_password(self, password):
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return base64.b64encode(salt + key).decode('utf-8')

    def verify_password(self, stored_hash, password):
        try:
            decoded = base64.b64decode(stored_hash)
            salt = decoded[:32]
            stored_key = decoded[32:]
            key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
            return stored_key == key
        except Exception:
            return False

    def create_user(self, username, password, avatar_data=None):
        user_id = str(uuid4())
        password_hash = self.hash_password(password)
        avatar_url = None

        if avatar_data:
            try:
                avatar_dir = Path('static/avatars')
                avatar_dir.mkdir(parents=True, exist_ok=True)
                # Extraer datos base64
                if ',' in avatar_data:
                    header, data = avatar_data.split(',', 1)
                else:
                    data = avatar_data
                    header = 'data:image/jpeg;base64'
                
                data = base64.b64decode(data)
                ext = 'png' if 'png' in header else 'jpg'
                filename = f"{user_id}.{ext}"
                filepath = avatar_dir / filename
                
                with open(filepath, 'wb') as f:
                    f.write(data)
                avatar_url = f"/avatars/{filename}"
                logger.info(f"Avatar guardado: {avatar_url}")
            except Exception as e:
                logger.error(f"Error procesando avatar: {e}")
                avatar_url = None

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (id, username, password_hash, avatar_url, is_online)
                    VALUES (?, ?, ?, ?, 0)
                ''', (user_id, username, password_hash, avatar_url))
                conn.commit()
                return {'id': user_id, 'username': username, 'avatar_url': avatar_url}
        except sqlite3.IntegrityError:
            return None

    def verify_user(self, username, password):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            if user and self.verify_password(user['password_hash'], password):
                return {'id': user['id'], 'username': user['username'], 'avatar_url': user['avatar_url']}
            return None

    def get_user(self, user_id):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            if user:
                return {'id': user['id'], 'username': user['username'], 'avatar_url': user['avatar_url']}
            return None

    def update_user_status(self, user_id, is_online):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET is_online = ?, last_seen = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (1 if is_online else 0, user_id))
            conn.commit()

    def get_all_users(self, exclude_user_id=None):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if exclude_user_id:
                cursor.execute('SELECT * FROM users WHERE id != ? ORDER BY username', (exclude_user_id,))
            else:
                cursor.execute('SELECT * FROM users ORDER BY username')
            users = cursor.fetchall()
            return [{
                'id': u['id'],
                'username': u['username'],
                'avatar_url': u['avatar_url'],
                'is_connected': bool(u['is_online']),
                'status': u['status']
            } for u in users]

    def create_session(self, user_id):
        token = str(uuid4())
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sessions (token, user_id, expires_at)
                VALUES (?, ?, datetime('now', '+1 day'))
            ''', (token, user_id))
            conn.commit()
        return token

    def validate_session(self, token):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT user_id FROM sessions 
                WHERE token = ? AND expires_at > datetime('now')
            ''', (token,))
            result = cursor.fetchone()
            return result['user_id'] if result else None

    def delete_session(self, token):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM sessions WHERE token = ?', (token,))
            conn.commit()

db_manager = DatabaseManager()

class UserManager:
    def __init__(self, db):
        self.db = db
        self.connected_users = {}
        self.call_handlers = {}

    def add_connected_user(self, user_id, ws, user_data):
        self.connected_users[user_id] = {
            'ws': ws,
            'username': user_data['username'],
            'avatar_url': user_data.get('avatar_url'),
            'last_ping': time.time()
        }
        self.db.update_user_status(user_id, True)
        logger.info(f"Usuario conectado: {user_data['username']} ({user_id})")

    def remove_connected_user(self, user_id):
        if user_id in self.connected_users:
            self.db.update_user_status(user_id, False)
            # Notificar a todos que este usuario se desconectó
            for uid, data in self.connected_users.items():
                if uid != user_id and 'ws' in data:
                    try:
                        asyncio.create_task(data['ws'].send_json({
                            'type': 'user_disconnected',
                            'userId': user_id
                        }))
                    except:
                        pass
            del self.connected_users[user_id]
            logger.info(f"Usuario desconectado: {user_id}")

    def get_connected_users(self, exclude_id=None):
        users = []
        for uid, data in self.connected_users.items():
            if uid != exclude_id:
                users.append({
                    'id': uid,
                    'username': data['username'],
                    'avatar_url': data['avatar_url'],
                    'status': 'disponible'
                })
        return users

    def register_call_handler(self, from_user, to_user, handler):
        key = f"{from_user}_{to_user}"
        self.call_handlers[key] = handler

    def get_call_handler(self, from_user, to_user):
        key = f"{from_user}_{to_user}"
        return self.call_handlers.get(key)

user_manager = UserManager(db_manager)

async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    token = request.query.get('token')
    if not token:
        await ws.close()
        return ws

    user_id = db_manager.validate_session(token)
    if not user_id:
        await ws.close()
        return ws

    user_data = db_manager.get_user(user_id)
    if not user_data:
        await ws.close()
        return ws

    user_manager.add_connected_user(user_id, ws, user_data)

    # Enviar registro exitoso con TODOS los usuarios
    await ws.send_json({
        'type': 'registered',
        'userId': user_id,
        'username': user_data['username'],
        'avatar_url': user_data.get('avatar_url'),
        'onlineUsers': user_manager.get_connected_users(user_id)
    })

    # Notificar a otros usuarios que este usuario se conectó
    for uid, data in user_manager.connected_users.items():
        if uid != user_id and 'ws' in data:
            try:
                await data['ws'].send_json({
                    'type': 'user_connected',
                    'userId': user_id,
                    'username': user_data['username'],
                    'avatar_url': user_data.get('avatar_url')
                })
            except:
                pass

    try:
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    msg_type = data.get('type')

                    if msg_type == 'get_users':
                        await ws.send_json({
                            'type': 'user_list',
                            'users': db_manager.get_all_users(user_id)
                        })

                    elif msg_type == 'call_request':
                        target_id = data.get('targetId')
                        if target_id in user_manager.connected_users:
                            target_ws = user_manager.connected_users[target_id]['ws']
                            await target_ws.send_json({
                                'type': 'incoming_call',
                                'callerId': user_id,
                                'callerName': user_data['username'],
                                'callerAvatar': user_data.get('avatar_url')
                            })
                            # Registrar el handler de llamada
                            user_manager.register_call_handler(user_id, target_id, ws)

                    elif msg_type == 'call_accept':
                        caller_id = data.get('callerId')
                        if caller_id in user_manager.connected_users:
                            caller_ws = user_manager.connected_users[caller_id]['ws']
                            await caller_ws.send_json({
                                'type': 'call_accepted',
                                'calleeId': user_id,
                                'calleeName': user_data['username']
                            })
                            # Registrar el handler inverso
                            user_manager.register_call_handler(user_id, caller_id, ws)

                    elif msg_type == 'call_decline':
                        caller_id = data.get('callerId')
                        if caller_id in user_manager.connected_users:
                            caller_ws = user_manager.connected_users[caller_id]['ws']
                            await caller_ws.send_json({
                                'type': 'call_declined',
                                'calleeId': user_id
                            })

                    elif msg_type == 'call_end':
                        target_id = data.get('targetId')
                        if target_id in user_manager.connected_users:
                            target_ws = user_manager.connected_users[target_id]['ws']
                            await target_ws.send_json({
                                'type': 'call_ended',
                                'from': user_id
                            })

                    elif msg_type == 'webrtc_signal':
                        target_id = data.get('targetId')
                        signal_data = data.get('signal')
                        
                        if target_id in user_manager.connected_users:
                            target_ws = user_manager.connected_users[target_id]['ws']
                            await target_ws.send_json({
                                'type': 'webrtc_signal',
                                'signal': signal_data,
                                'from': user_id
                            })
                        else:
                            logger.warning(f"Usuario objetivo {target_id} no conectado")

                    elif msg_type == 'ping':
                        # Actualizar último ping
                        if user_id in user_manager.connected_users:
                            user_manager.connected_users[user_id]['last_ping'] = time.time()
                            await ws.send_json({'type': 'pong'})

                except Exception as e:
                    logger.error(f"Error procesando mensaje: {e}")
                    await ws.send_json({
                        'type': 'error',
                        'message': str(e)
                    })

            elif msg.type == web.WSMsgType.ERROR:
                logger.error(f'Error en WebSocket: {ws.exception()}')

    except Exception as e:
        logger.error(f"Error en conexión WebSocket: {e}")
    finally:
        user_manager.remove_connected_user(user_id)
    
    return ws

async def handle_login(request):
    token = request.cookies.get('webrtc_session_token')
    if token and db_manager.validate_session(token):
        return web.HTTPFound('/index')
    return web.FileResponse('login.html')

async def handle_index(request):
    token = request.cookies.get('webrtc_session_token')
    
    if not token:
        return web.HTTPFound('/')
    
    user_id = db_manager.validate_session(token)
    if not user_id:
        response = web.HTTPFound('/')
        response.del_cookie('webrtc_session_token')
        return response
    
    return web.FileResponse('index.html')

async def handle_static(request):
    path = request.match_info.get('path', '')
    
    allowed_paths = [
        'login.html', 'index.html', 'manifest.json',
        'service-worker.js', 'register-sw.js'
    ]
    
    if path in allowed_paths:
        full_path = Path('.') / path
        if full_path.is_file():
            return web.FileResponse(full_path)
    
    if path.startswith('icons/') or path.startswith('static/'):
        full_path = Path('.') / path
        if full_path.is_file():
            return web.FileResponse(full_path)
    
    return web.Response(status=404)

async def handle_avatar(request):
    path = request.match_info.get('path', '')
    full_path = Path('static/avatars') / path
    
    Path('static/avatars').mkdir(parents=True, exist_ok=True)
    
    if not full_path.is_file():
        # Devolver imagen por defecto
        default_avatar = Path('static/default-avatar.png')
        if default_avatar.is_file():
            return web.FileResponse(default_avatar)
        return web.Response(status=404)
    
    response = web.FileResponse(full_path)
    response.headers['Cache-Control'] = 'public, max-age=31536000'
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

async def handle_register(request):
    try:
        data = await request.json()
    except Exception as e:
        logger.error(f"Error parsing register data: {e}")
        return web.json_response({'success': False, 'error': 'Datos inválidos'})
    
    username = data.get('username')
    password = data.get('password')
    avatar = data.get('avatar')

    if not username or not password:
        return web.json_response({'success': False, 'error': 'Faltan campos'})

    user = db_manager.create_user(username, password, avatar)
    if user:
        token = db_manager.create_session(user['id'])
        response = web.json_response({
            'success': True, 
            'user': user, 
            'token': token
        })
        response.set_cookie('webrtc_session_token', token, max_age=86400, httponly=True, samesite='Strict')
        return response
    return web.json_response({'success': False, 'error': 'Usuario ya existe'})

async def handle_login_api(request):
    try:
        data = await request.json()
    except Exception:
        return web.json_response({'success': False, 'error': 'Datos inválidos'})
    
    username = data.get('username')
    password = data.get('password')
    user = db_manager.verify_user(username, password)
    if user:
        token = db_manager.create_session(user['id'])
        response = web.json_response({
            'success': True, 
            'user': user, 
            'token': token
        })
        response.set_cookie('webrtc_session_token', token, max_age=86400, httponly=True, samesite='Strict')
        return response
    return web.json_response({'success': False, 'error': 'Credenciales inválidas'})

async def handle_logout(request):
    token = request.cookies.get('webrtc_session_token')
    if token:
        db_manager.delete_session(token)
    
    response = web.HTTPFound('/')
    response.del_cookie('webrtc_session_token')
    return response

async def handle_health(request):
    """Endpoint de salud para Render"""
    return web.json_response({
        'status': 'ok',
        'timestamp': time.time(),
        'connected_users': len(user_manager.connected_users)
    })

async def handle_update_profile(request):
    """Actualizar perfil de usuario"""
    token = request.cookies.get('webrtc_session_token')
    if not token:
        return web.json_response({'success': False, 'error': 'No autenticado'})
    
    user_id = db_manager.validate_session(token)
    if not user_id:
        return web.json_response({'success': False, 'error': 'Sesión inválida'})
    
    try:
        data = await request.json()
    except Exception:
        return web.json_response({'success': False, 'error': 'Datos inválidos'})
    
    # Aquí implementarías la actualización del perfil
    # Por ahora solo un placeholder
    return web.json_response({'success': True, 'message': 'Perfil actualizado'})

async def start_server():
    port = int(os.environ.get("PORT", 3000))
    
    # Crear directorios necesarios
    Path('static/avatars').mkdir(parents=True, exist_ok=True)
    Path('icons').mkdir(exist_ok=True)
    
    app = web.Application()

    # Rutas API
    app.router.add_get('/ws', websocket_handler)
    app.router.add_post('/api/register', handle_register)
    app.router.add_post('/api/login', handle_login_api)
    app.router.add_get('/api/logout', handle_logout)
    app.router.add_get('/api/health', handle_health)
    app.router.add_post('/api/update-profile', handle_update_profile)
    
    # Rutas de páginas
    app.router.add_get('/', handle_login)
    app.router.add_get('/index', handle_index)
    
    # Rutas de archivos estáticos
    app.router.add_get('/avatars/{path:.*}', handle_avatar)
    app.router.add_get('/icons/{path:.*}', handle_static)
    app.router.add_get('/{path:.*}', handle_static)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', port)
    await site.start()
    
    print(f"✅ Servidor WebRTC iniciado en puerto {port}")
    print(f"🌐 Accede en: http://localhost:{port}")
    print(f"📁 Base de datos: webrtc.db")
    print(f"👤 Directorio de avatares: static/avatars/")
    print(f"🎨 Directorio de iconos: icons/")
    print(f"🏥 Health check: http://localhost:{port}/api/health")

    # Mantener el servidor corriendo
    await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        print("\n👋 Servidor detenido")