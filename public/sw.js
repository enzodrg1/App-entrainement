const C = 'coaching-trail-v14';
const ASSETS = ['./','./index.html','./plan.json','./manifest.webmanifest','./icon-192.png','./icon-512.png','./icon-512-maskable.png','./apple-touch-icon.png'];

// addAll() rejette EN BLOC : un seul asset manquant (404 sur plan.json par ex.)
// empechait l'installation du nouveau SW et laissait l'ancien cache actif.
// On met donc en cache asset par asset, en tolerant les echecs individuels.
self.addEventListener('install', function(e){
  e.waitUntil(
    caches.open(C).then(function(c){
      return Promise.all(ASSETS.map(function(u){
        return fetch(new Request(u, {cache:'reload'})).then(function(res){
          if(!res || !res.ok) return null;          // jamais de reponse en erreur en cache
          return c.put(u, res);
        }).catch(function(){ return null; });
      }));
    }).then(function(){ return self.skipWaiting(); })
     .catch(function(){ return self.skipWaiting(); })
  );
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
  // Les fonctions serverless ne doivent JAMAIS etre interceptees : ni mises en
  // cache, ni servies depuis le cache, ni utilisees comme reponse de repli.
  // On sort AVANT toute autre branche : sans respondWith, le navigateur fait
  // sa requete reseau normale.
  try{
    var fnUrl = new URL(req.url);
    if(fnUrl.pathname.indexOf('/.netlify/functions/') === 0) return;
  }catch(_){}

  var accept = req.headers.get('accept') || '';
  var isHTML = req.mode==='navigate' || accept.indexOf('text/html')>-1;

  // plan.json : network-first comme le HTML. En cache-first, une mise a jour du plan
  // ne descendrait jamais sur le telephone.
  var isPlan = false;
  try{
    var u = new URL(req.url);
    isPlan = (u.origin===location.origin) && /\/plan\.json$/.test(u.pathname);
  }catch(_){}

  if(isHTML || isPlan){
    // Network-first : toujours la derniere version, cache en secours (hors-ligne)
    e.respondWith(
      fetch(req).then(function(res){
        // B12 : ne JAMAIS mettre en cache une reponse en erreur (404, 500, page de
        // portail captif...), sinon elle est resservie hors-ligne a la place du bon fichier.
        if(res && res.ok){
          var copy = res.clone(); caches.open(C).then(function(c){c.put(req, copy);}).catch(function(){});
        }
        return res;
      }).catch(function(){
        return caches.match(req).then(function(r){
          if(r) return r;
          if(isPlan) return caches.match('./plan.json');
          return caches.match('./index.html');
        });
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
          // B12 : res.ok obligatoire avant tout cache.put.
          if(res && res.ok && (url.origin===location.origin || url.host.indexOf('fonts.g')>-1)){
            var copy = res.clone(); caches.open(C).then(function(c){c.put(req, copy);}).catch(function(){});
          }
        }catch(_){}
        return res;
      }).catch(function(){ return cached; });
    })
  );
});
