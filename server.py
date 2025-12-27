#!/usr/bin/env python3
"""
SERVIDOR WEBRTC OPTIMIZADO - LLAMADAS DE VOZ
"""

import asyncio
import json
from aiohttp import web
import logging
import os
import sys
from uuid import uuid4
import hashlib
import base64
import sqlite3
from pathlib import Path
import time

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class Config:
    DATABASE_PATH = 'webrtc.db'
    STATIC_DIR = 'static'
    AVATARS_DIR = 'static/avatars'
    PORT = int(os.environ.get("PORT", 3000))
    PING_TIMEOUT = 30
    CLEANUP_INTERVAL = 60

class DatabaseManager:
    def __init__(self, db_path=Config.DATABASE_PATH):
        self.db_path = db_path
        self.init_database()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_database(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Tabla de usuarios
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    avatar_url TEXT,
                    is_online BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabla de sesiones
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP DEFAULT (datetime('now', '+1 day')),
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')
            
            conn.commit()
        
        logger.info("Base de datos inicializada")

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
                Path(Config.AVATARS_DIR).mkdir(parents=True, exist_ok=True)
                
                if ',' in avatar_data:
                    header, data = avatar_data.split(',', 1)
                else:
                    data = avatar_data
                    header = 'data:image/jpeg;base64'
                
                data = base64.b64decode(data)
                ext = 'png' if 'png' in header else 'jpg'
                filename = f"{user_id}.{ext}"
                filepath = Path(Config.AVATARS_DIR) / filename

                with open(filepath, 'wb') as f:
                    f.write(data)
                avatar_url = f"/avatars/{filename}"
            except Exception as e:
                logger.error(f"Error procesando avatar: {e}")
                avatar_url = None

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (id, username, password_hash, avatar_url, is_online)
                    VALUES (?, ?, ?, ?, 0)
                ''', (user_id, username, password_hash, avatar_url))
                conn.commit()
                
                return {
                    'id': user_id,
                    'username': username,
                    'avatar_url': avatar_url,
                    'is_online': False
                }
        except sqlite3.IntegrityError:
            return None

    def verify_user(self, username, password):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            
            if user and self.verify_password(user['password_hash'], password):
                return {
                    'id': user['id'],
                    'username': user['username'],
                    'avatar_url': user['avatar_url'],
                    'is_online': bool(user['is_online'])
                }
            return None

    def get_user(self, user_id):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            
            if user:
                return {
                    'id': user['id'],
                    'username': user['username'],
                    'avatar_url': user['avatar_url'],
                    'is_online': bool(user['is_online'])
                }
            return None

    def update_user_status(self, user_id, is_online=True):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET is_online = ?, last_seen = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (1 if is_online else 0, user_id))
            conn.commit()

    def get_all_users(self, exclude_user_id=None):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if exclude_user_id:
                cursor.execute('''
                    SELECT id, username, avatar_url, is_online
                    FROM users 
                    WHERE id != ?
                    ORDER BY username
                ''', (exclude_user_id,))
            else:
                cursor.execute('''
                    SELECT id, username, avatar_url, is_online
                    FROM users 
                    ORDER BY username
                ''')
            
            users = cursor.fetchall()
            return [{
                'id': u['id'],
                'username': u['username'],
                'avatar_url': u['avatar_url'],
                'is_connected': bool(u['is_online'])
            } for u in users]

    def create_session(self, user_id):
        token = str(uuid4())
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sessions (token, user_id)
                VALUES (?, ?)
            ''', (token, user_id))
            conn.commit()
        return token

    def validate_session(self, token):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT user_id FROM sessions 
                WHERE token = ? AND expires_at > datetime('now')
            ''', (token,))
            result = cursor.fetchone()
            return result['user_id'] if result else None

    def delete_session(self, token):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM sessions WHERE token = ?', (token,))
            conn.commit()

db_manager = DatabaseManager()

class Connection:
    def __init__(self, ws, user_id, user_data):
        self.ws = ws
        self.user_id = user_id
        self.username = user_data['username']
        self.avatar_url = user_data.get('avatar_url')
        self.last_ping = time.time()
        self.in_call_with = None
        self.call_id = None

class UserManager:
    def __init__(self):
        self.connections = {}
        self.active_calls = {}
        self.lock = asyncio.Lock()

    async def add_connection(self, user_id, ws, user_data):
        async with self.lock:
            if user_id in self.connections:
                old_conn = self.connections[user_id]
                if old_conn.ws and not old_conn.ws.closed:
                    try:
                        await old_conn.ws.close()
                    except:
                        pass
            
            conn = Connection(ws, user_id, user_data)
            self.connections[user_id] = conn
            
            db_manager.update_user_status(user_id, True)
            logger.info(f"Usuario conectado: {user_data['username']}")
            return conn

    async def remove_connection(self, user_id):
        async with self.lock:
            if user_id in self.connections:
                conn = self.connections[user_id]
                
                # Terminar llamadas activas
                if conn.call_id:
                    await self.end_call(conn.call_id, f"Usuario {user_id} desconectado")
                
                # Actualizar estado
                db_manager.update_user_status(user_id, False)
                
                # Notificar a otros
                await self.notify_user_disconnected(user_id)
                
                del self.connections[user_id]
                logger.info(f"Usuario desconectado: {conn.username}")

    def get_connection(self, user_id):
        return self.connections.get(user_id)

    async def notify_user_connected(self, user_id):
        conn = self.get_connection(user_id)
        if not conn:
            return
        
        notification = {
            'type': 'user_connected',
            'userId': user_id,
            'username': conn.username,
            'avatar_url': conn.avatar_url
        }
        
        tasks = []
        for uid, other_conn in self.connections.items():
            if uid != user_id and other_conn.ws and not other_conn.ws.closed:
                tasks.append(other_conn.ws.send_json(notification))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def notify_user_disconnected(self, user_id):
        notification = {
            'type': 'user_disconnected',
            'userId': user_id
        }
        
        tasks = []
        for uid, conn in self.connections.items():
            if uid != user_id and conn.ws and not conn.ws.closed:
                tasks.append(conn.ws.send_json(notification))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def start_call(self, caller_id, callee_id):
        async with self.lock:
            caller_conn = self.get_connection(caller_id)
            callee_conn = self.get_connection(callee_id)
            
            if not caller_conn or not callee_conn:
                return None
            
            # Verificar si ya están en llamada
            if caller_conn.in_call_with or callee_conn.in_call_with:
                return None
            
            call_id = str(uuid4())
            
            # Actualizar estados
            caller_conn.in_call_with = callee_id
            callee_conn.in_call_with = caller_id
            caller_conn.call_id = call_id
            callee_conn.call_id = call_id
            
            # Registrar llamada
            self.active_calls[call_id] = {
                'id': call_id,
                'caller_id': caller_id,
                'callee_id': callee_id,
                'started_at': time.time(),
                'status': 'ringing'
            }
            
            # Notificar al receptor
            if callee_conn.ws and not callee_conn.ws.closed:
                await callee_conn.ws.send_json({
                    'type': 'incoming_call',
                    'callId': call_id,
                    'callerId': caller_id,
                    'callerName': caller_conn.username,
                    'callerAvatar': caller_conn.avatar_url
                })
            
            logger.info(f"Llamada iniciada: {call_id}")
            return call_id

    async def accept_call(self, call_id, callee_id):
        async with self.lock:
            if call_id not in self.active_calls:
                return False
            
            call = self.active_calls[call_id]
            if call['callee_id'] != callee_id:
                return False
            
            caller_conn = self.get_connection(call['caller_id'])
            callee_conn = self.get_connection(callee_id)
            
            if not caller_conn or not callee_conn:
                return False
            
            # Actualizar estado
            call['status'] = 'active'
            call['answered_at'] = time.time()
            
            # Notificar al llamante
            if caller_conn.ws and not caller_conn.ws.closed:
                await caller_conn.ws.send_json({
                    'type': 'call_accepted',
                    'callId': call_id,
                    'calleeId': callee_id,
                    'calleeName': callee_conn.username
                })
            
            logger.info(f"Llamada aceptada: {call_id}")
            return True

    async def reject_call(self, call_id, callee_id):
        async with self.lock:
            if call_id not in self.active_calls:
                return False
            
            call = self.active_calls[call_id]
            caller_conn = self.get_connection(call['caller_id'])
            
            if caller_conn and caller_conn.ws and not caller_conn.ws.closed:
                await caller_conn.ws.send_json({
                    'type': 'call_declined',
                    'callId': call_id,
                    'calleeId': callee_id
                })
            
            await self.cleanup_call(call_id)
            logger.info(f"Llamada rechazada: {call_id}")
            return True

    async def end_call(self, call_id, reason='ended'):
        async with self.lock:
            if call_id not in self.active_calls:
                return False
            
            call = self.active_calls[call_id]
            caller_conn = self.get_connection(call['caller_id'])
            callee_conn = self.get_connection(call['callee_id'])
            
            # Notificar a ambos
            for conn in [caller_conn, callee_conn]:
                if conn and conn.ws and not conn.ws.closed:
                    await conn.ws.send_json({
                        'type': 'call_ended',
                        'callId': call_id,
                        'reason': reason
                    })
            
            await self.cleanup_call(call_id)
            logger.info(f"Llamada terminada: {call_id}")
            return True

    async def cleanup_call(self, call_id):
        if call_id in self.active_calls:
            call = self.active_calls[call_id]
            
            # Liberar usuarios
            for user_id in [call['caller_id'], call['callee_id']]:
                conn = self.get_connection(user_id)
                if conn and conn.call_id == call_id:
                    conn.in_call_with = None
                    conn.call_id = None
            
            # Eliminar de estructuras
            del self.active_calls[call_id]

    async def forward_signal(self, from_user, to_user, signal_data):
        from_conn = self.get_connection(from_user)
        to_conn = self.get_connection(to_user)
        
        if not from_conn or not to_conn:
            return False
        
        # Verificar que están en la misma llamada
        if from_conn.in_call_with != to_user:
            logger.warning(f"Intento de señal entre usuarios no en llamada")
            return False
        
        if to_conn.ws and not to_conn.ws.closed:
            await to_conn.ws.send_json({
                'type': 'webrtc_signal',
                'signal': signal_data,
                'from': from_user
            })
            return True
        
        return False

    def get_connected_users(self, exclude_id=None):
        users = []
        for user_id, conn in self.connections.items():
            if exclude_id and user_id == exclude_id:
                continue
            
            users.append({
                'id': user_id,
                'username': conn.username,
                'avatar_url': conn.avatar_url,
                'is_connected': True
            })
        return users

    async def cleanup_inactive_connections(self):
        async with self.lock:
            current_time = time.time()
            to_remove = []
            
            for user_id, conn in self.connections.items():
                if current_time - conn.last_ping > Config.PING_TIMEOUT:
                    to_remove.append(user_id)
            
            for user_id in to_remove:
                await self.remove_connection(user_id)
            
            return len(to_remove)

user_manager = UserManager()

async def cleanup_task():
    """Tarea periódica de limpieza"""
    while True:
        try:
            removed = await user_manager.cleanup_inactive_connections()
            if removed > 0:
                logger.info(f"Limpieza: {removed} conexiones eliminadas")
        except Exception as e:
            logger.error(f"Error en limpieza: {e}")
        
        await asyncio.sleep(Config.CLEANUP_INTERVAL)

async def websocket_handler(request):
    """Manejador WebSocket"""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    
    token = request.query.get('token')
    if not token:
        await ws.close(code=4001, message='Token requerido')
        return ws
    
    user_id = db_manager.validate_session(token)
    if not user_id:
        await ws.close(code=4001, message='Token inválido')
        return ws
    
    user_data = db_manager.get_user(user_id)
    if not user_data:
        await ws.close(code=4001, message='Usuario no encontrado')
        return ws
    
    conn = await user_manager.add_connection(user_id, ws, user_data)
    
    try:
        # Enviar registro exitoso
        await ws.send_json({
            'type': 'registered',
            'userId': user_id,
            'username': user_data['username'],
            'avatar_url': user_data.get('avatar_url'),
            'onlineUsers': user_manager.get_connected_users(user_id)
        })
        
        # Notificar a otros usuarios
        await user_manager.notify_user_connected(user_id)
        
        # Loop principal de mensajes
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                try:
                    conn.last_ping = time.time()
                    data = json.loads(msg.data)
                    msg_type = data.get('type')
                    
                    if msg_type == 'ping':
                        await ws.send_json({'type': 'pong'})
                        
                    elif msg_type == 'get_users':
                        await ws.send_json({
                            'type': 'user_list',
                            'users': user_manager.get_connected_users(user_id)
                        })
                        
                    elif msg_type == 'call_request':
                        target_id = data.get('targetId')
                        if target_id:
                            call_id = await user_manager.start_call(user_id, target_id)
                            if call_id:
                                await ws.send_json({
                                    'type': 'call_initiated',
                                    'callId': call_id
                                })
                            else:
                                await ws.send_json({
                                    'type': 'error',
                                    'message': 'No se pudo iniciar la llamada'
                                })
                        
                    elif msg_type == 'call_accept':
                        call_id = data.get('callId')
                        if call_id:
                            await user_manager.accept_call(call_id, user_id)
                        
                    elif msg_type == 'call_decline':
                        call_id = data.get('callId')
                        if call_id:
                            await user_manager.reject_call(call_id, user_id)
                        
                    elif msg_type == 'call_end':
                        call_id = data.get('callId')
                        if call_id:
                            await user_manager.end_call(call_id, 'ended_by_user')
                        
                    elif msg_type == 'webrtc_signal':
                        target_id = data.get('targetId')
                        signal_data = data.get('signal')
                        if target_id and signal_data:
                            await user_manager.forward_signal(user_id, target_id, signal_data)
                        
                except json.JSONDecodeError as e:
                    logger.error(f"JSON inválido: {e}")
                except Exception as e:
                    logger.error(f"Error procesando mensaje: {e}")
            
            elif msg.type == web.WSMsgType.ERROR:
                logger.error(f'Error en WebSocket: {ws.exception()}')
                break
        
    except Exception as e:
        logger.error(f"Error en conexión: {e}")
    finally:
        await user_manager.remove_connection(user_id)
    
    return ws

async def handle_login(request):
    """Página de login"""
    token = request.cookies.get('webrtc_session_token')
    if token and db_manager.validate_session(token):
        return web.HTTPFound('/index')
    return web.FileResponse('login.html')

async def handle_index(request):
    """Página principal"""
    token = request.cookies.get('webrtc_session_token')
    
    if not token:
        return web.HTTPFound('/')
    
    user_id = db_manager.validate_session(token)
    if not user_id:
        response = web.HTTPFound('/')
        response.del_cookie('webrtc_session_token')
        return response
    
    return web.FileResponse('index.html')

async def handle_avatar(request):
    """Servir avatares"""
    path = request.match_info.get('path', '')
    full_path = Path(Config.AVATARS_DIR) / path
    
    Path(Config.AVATARS_DIR).mkdir(parents=True, exist_ok=True)
    
    if not full_path.is_file():
        return web.Response(status=404)
    
    response = web.FileResponse(full_path)
    response.headers['Cache-Control'] = 'public, max-age=31536000'
    return response

async def handle_register(request):
    """Registro de usuario"""
    try:
        data = await request.json()
    except Exception:
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
    """Login API"""
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
    """Logout"""
    token = request.cookies.get('webrtc_session_token')
    if token:
        db_manager.delete_session(token)
    
    response = web.HTTPFound('/')
    response.del_cookie('webrtc_session_token')
    return response

async def handle_health(request):
    """Health check"""
    return web.json_response({
        'status': 'ok',
        'timestamp': time.time(),
        'connected_users': len(user_manager.connections)
    })

async def handle_static(request):
    """Archivos estáticos"""
    path = request.match_info.get('path', '')
    
    allowed_paths = [
        'login.html', 'index.html', 'manifest.json',
        'service-worker.js'
    ]
    
    if path in allowed_paths:
        full_path = Path('.') / path
        if full_path.is_file():
            return web.FileResponse(full_path)
    
    if path.startswith('icons/'):
        full_path = Path('.') / path
        if full_path.is_file():
            return web.FileResponse(full_path)
    
    return web.Response(status=404)

async def start_server():
    """Iniciar servidor"""
    port = Config.PORT
    
    # Crear directorios
    Path(Config.AVATARS_DIR).mkdir(parents=True, exist_ok=True)
    Path('icons').mkdir(exist_ok=True)
    
    app = web.Application()
    
    # API routes
    app.router.add_get('/ws', websocket_handler)
    app.router.add_post('/api/register', handle_register)
    app.router.add_post('/api/login', handle_login_api)
    app.router.add_get('/api/logout', handle_logout)
    app.router.add_get('/api/health', handle_health)
    
    # Page routes
    app.router.add_get('/', handle_login)
    app.router.add_get('/index', handle_index)
    
    # Static routes
    app.router.add_get('/avatars/{path:.*}', handle_avatar)
    app.router.add_get('/icons/{path:.*}', handle_static)
    app.router.add_get('/{path:.*}', handle_static)
    
    # Iniciar tarea de limpieza
    asyncio.create_task(cleanup_task())
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', port)
    await site.start()
    
    print(f"✅ Servidor iniciado en puerto {port}")
    print(f"🌐 Accede en: http://localhost:{port}")
    print(f"🏥 Health: http://localhost:{port}/api/health")
    
    await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        print("\n👋 Servidor detenido")