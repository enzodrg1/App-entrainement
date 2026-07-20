const C = 'montberou-v4';
const ASSETS = ['./','./index.html','./manifest.webmanifest','./icon-192.png','./icon-512.png','./icon-512-maskable.png','./apple-touch-icon.png'];
self.addEventListener('install', function(e){ e.waitUntil(caches.open(C).then(function(c){return c.addAll(ASSETS);}).then(function(){return self.skipWaiting();})); });
self.addEventListener('activate', function(e){ e.waitUntil(caches.keys().then(function(ks){return Promise.all(ks.filter(function(k){return k!==C;}).map(function(k){return caches.delete(k);}));}).then(function(){return self.clients.claim();})); });
self.addEventListener('fetch', function(e){
  var req = e.request;
  if(req.method!=='GET') return;
  e.respondWith(
    caches.match(req).then(function(cached){
      return cached || fetch(req).then(function(res){
        try{
          var url = new URL(req.url);
          if(url.origin===location.origin || url.host.indexOf('fonts.g')>-1){
            var copy = res.clone(); caches.open(C).then(function(c){c.put(req, copy);});
          }
        }catch(_){}
        return res;
      }).catch(function(){ return cached; });
    })
  );
});
