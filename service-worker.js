const CACHE_NAME = 'webrtc-calls-v2';
const STATIC_CACHE_NAME = 'webrtc-calls-static-v2';

const STATIC_FILES = [
  '/',
  '/index.html',
  '/login.html',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/icon-180.png',
  'https://cdn.jsdelivr.net/npm/simple-peer@9.11.1/simplepeer.min.js',
  'https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css'
];

// Instalar service worker
self.addEventListener('install', (event) => {
  console.log('[Service Worker] Instalando...');
  event.waitUntil(
    caches.open(STATIC_CACHE_NAME).then((cache) => {
      console.log('[Service Worker] Cacheando archivos estáticos');
      return cache.addAll(STATIC_FILES).catch(err => {
        console.log('Error cacheando algunos archivos:', err);
      });
    }).then(() => {
      return self.skipWaiting();
    })
  );
});

// Activar y limpiar caches viejos
self.addEventListener('activate', (event) => {
  console.log('[Service Worker] Activando...');
  event.waitUntil(
    Promise.all([
      caches.keys().then((cacheNames) => {
        return Promise.all(
          cacheNames.map((cacheName) => {
            if (cacheName !== STATIC_CACHE_NAME && cacheName !== CACHE_NAME) {
              console.log('[Service Worker] Borrando cache viejo:', cacheName);
              return caches.delete(cacheName);
            }
          })
        );
      }),
      self.clients.claim()
    ])
  );
});

// Estrategia de cache: Network First para API, Cache First para estáticos
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  
  // No cachear WebSocket, API o avatares
  if (url.pathname.startsWith('/ws') || 
      url.pathname.startsWith('/api/') ||
      url.pathname.startsWith('/avatars/')) {
    return;
  }
  
  // Para archivos estáticos: Cache First
  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        // Actualizar cache en segundo plano
        event.waitUntil(
          fetch(event.request).then((response) => {
            if (response && response.status === 200) {
              const responseToCache = response.clone();
              caches.open(CACHE_NAME).then((cache) => {
                cache.put(event.request, responseToCache);
              });
            }
          }).catch(() => { /* Ignorar errores de actualización */ })
        );
        return cachedResponse;
      }
      
      // Si no está en cache, fetch de red
      return fetch(event.request).then((response) => {
        // Verificar respuesta válida
        if (!response || response.status !== 200 || response.type !== 'basic') {
          return response;
        }
        
        // Clonar respuesta para cache
        const responseToCache = response.clone();
        caches.open(CACHE_NAME).then((cache) => {
          cache.put(event.request, responseToCache);
        });
        
        return response;
      }).catch(() => {
        // Si falla la red y no está en cache, mostrar offline page
        if (event.request.mode === 'navigate') {
          return caches.match('/offline.html') || 
                 new Response('Estás offline. Por favor, revisa tu conexión.', {
                   status: 200,
                   headers: { 'Content-Type': 'text/html' }
                 });
        }
        return new Response('Network error', { status: 408 });
      });
    })
  );
});

// Manejar notificaciones push (para futuras llamadas)
self.addEventListener('push', (event) => {
  if (!event.data) return;
  
  const data = event.data.json();
  const options = {
    body: data.body || 'Tienes una llamada entrante 📞',
    icon: '/icons/icon-192.png',
    badge: '/icons/icon-72.png',
    vibrate: [200, 100, 200, 100, 200],
    data: {
      url: data.url || '/',
      callerId: data.callerId
    },
    actions: [
      {
        action: 'answer',
        title: 'Responder',
        icon: '/icons/answer.png'
      },
      {
        action: 'decline',
        title: 'Rechazar',
        icon: '/icons/decline.png'
      }
    ],
    requireInteraction: true
  };
  
  event.waitUntil(
    self.registration.showNotification(data.title || 'Llamada WebRTC', options)
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  
  const urlToOpen = event.notification.data.url;
  
  event.waitUntil(
    clients.matchAll({
      type: 'window',
      includeUncontrolled: true
    }).then((windowClients) => {
      // Verificar si ya hay una ventana abierta
      for (const client of windowClients) {
        if (client.url === urlToOpen && 'focus' in client) {
          return client.focus();
        }
      }
      
      // Si no hay ventana abierta, abrir una nueva
      if (clients.openWindow) {
        return clients.openWindow(urlToOpen);
      }
    })
  );
});

// Comunicación con la app
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  
  if (event.data && event.data.type === 'GET_CACHE') {
    event.ports[0].postMessage({ cache: STATIC_CACHE_NAME });
  }
});