const C = 'coaching-trail-v5';
const ASSETS = ['./','./index.html','./manifest.webmanifest','./icon-192.png','./icon-512.png','./icon-512-maskable.png','./apple-touch-icon.png'];

self.addEventListener('install', function(e){
  e.waitUntil(caches.open(C).then(function(c){return c.addAll(ASSETS);}).then(function(){return self.skipWaiting();}));
});

self.addEventListener('activate', function(e){
  e.waitUntil(
    caches.keys().then(function(ks){
      return Promise.all(ks.filter(function(k){return k!==C;}).map(function(k){return caches.delete(k);}));
    }).then(function(){return self.clients.claim();})
  );
});

self.addEventListener('fetch', function(e){
  var req = e.request;
  if(req.method!=='GET') return;
  var accept = req.headers.get('accept') || '';
  var isHTML = req.mode==='navigate' || accept.indexOf('text/html')>-1;

  if(isHTML){
    // Network-first : toujours la derniere version, cache en secours (hors-ligne)
    e.respondWith(
      fetch(req).then(function(res){
        var copy = res.clone(); caches.open(C).then(function(c){c.put(req, copy);});
        return res;
      }).catch(function(){
        return caches.match(req).then(function(r){ return r || caches.match('./index.html'); });
      })
    );
    return;
  }

  // Cache-first pour les fichiers statiques (icones, polices)
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
