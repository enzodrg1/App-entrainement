const C = 'coaching-trail-v24';
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

/* CLE DE CACHE d'une requete : son URL DEBARRASSEE de sa query et de son
   fragment quand elle est de MEME ORIGINE.

   Deux exigences a tenir en meme temps :
   - `/?invite=<code>` ne doit laisser AUCUNE trace. Une entree de cache est
     un fichier qui reste sur le telephone : sous cette cle, la navigation
     est simplement rangee sous `/`.
   - `./` et `./index.html` sont DEUX entrees distinctes du cache, et les
     deux sont visees : manifest.webmanifest declare `start_url: "./"`.
     Mettre en cache sous une CONSTANTE (`'./index.html'`) ne rafraichissait
     que la seconde : l'entree `./`, celle que vise chaque lancement depuis
     l'ecran d'accueil, restait figee sur la version installee, et l'app
     differait selon qu'il y avait du reseau ou non -- sans auto-reparation.
     On met donc en cache sous l'URL REELLEMENT DEMANDEE, seulement nettoyee
     de sa query.

   Les requetes d'AUTRE ORIGINE gardent leur URL entiere : la query de la
   feuille de style Google Fonts PORTE la liste des familles, la depouiller
   ferait collisionner des ressources differentes et rendrait la police
   introuvable hors-ligne. Aucune requete d'autre origine ne transporte de
   code d'invitation : `?invite=` n'existe que sur une navigation vers ce
   site. */
function cacheKeyFor(req){
  try{
    var u = new URL(req.url);
    if(u.origin !== location.origin) return req;
    u.search = ''; u.hash = '';
    return u.href;
  }catch(_){ return req; }
}

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
    // Cle calculee UNE fois : elle sert a l'ecriture comme a la relecture
    // hors-ligne, sans quoi une entree rangee sous `/` ne serait jamais
    // retrouvee depuis `/?invite=<code>`.
    var ckey = cacheKeyFor(req);
    // Network-first : toujours la derniere version, cache en secours (hors-ligne)
    e.respondWith(
      fetch(req).then(function(res){
        // B12 : ne JAMAIS mettre en cache une reponse en erreur (404, 500, page de
        // portail captif...), sinon elle est resservie hors-ligne a la place du bon fichier.
        // La cle ne porte jamais de query : `?invite=<code>` ne peut pas se
        // retrouver dans le cache, et `./` comme `./index.html` sont chacune
        // rafraichies quand elles sont demandees.
        if(res && res.ok){
          var copy = res.clone();
          caches.open(C).then(function(c){c.put(ckey, copy);}).catch(function(){});
        }
        return res;
      }).catch(function(){
        // Hors-ligne : on cherche d'abord la cle NETTOYEE -- `/?invite=<code>`
        // retrouve ainsi l'entree `/` --, puis les deux replis canoniques.
        return caches.match(ckey).then(function(r){
          if(r) return r;
          if(isPlan) return caches.match('./plan.json');
          return caches.match('./index.html');
        });
      })
    );
    return;
  }

  // Cache-first pour les fichiers statiques (icones, polices)
  // Meme cle nettoyee : aucune entree de MEME ORIGINE ne porte de query.
  var skey = cacheKeyFor(req);
  e.respondWith(
    caches.match(skey).then(function(cached){
      return cached || fetch(req).then(function(res){
        try{
          var url = new URL(req.url);
          // B12 : res.ok obligatoire avant tout cache.put.
          if(res && res.ok && (url.origin===location.origin || url.host.indexOf('fonts.g')>-1)){
            var copy = res.clone(); caches.open(C).then(function(c){c.put(skey, copy);}).catch(function(){});
          }
        }catch(_){}
        return res;
      }).catch(function(){ return cached; });
    })
  );
});
