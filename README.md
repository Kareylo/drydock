# Drydock

Interface web pour mettre à jour les stacks Docker Compose de Portainer, avec analyse de version et mise en maintenance Pangolin pendant l'opération.

- Binaire Rust statique (musl, rustls/ring, sans OpenSSL), image `FROM scratch` (binaire + certificats CA).
- Aucun accès à la BDD Portainer : tout passe par l'API Portainer (clé API) et l'API d'intégration Pangolin.

## Ce que fait l'analyse

Pour chaque image de chaque stack :

| Cas | Détection | Type |
|---|---|---|
| Tag versionné (`8.34`, `18-alpine`, `v1.2.3`) avec un tag plus récent **dans la même majeure** | liste des tags du registre (même préfixe, même suffixe, même précision) | patch / mineure → appliquée automatiquement (le tag est réécrit dans le compose) |
| Tag versionné avec une **nouvelle majeure** (`postgres:18-alpine` → `19-alpine`) | idem | **jamais proposée**, comme avec diun : une montée de majeure se fait à la main dans le compose |
| Tag écrit dans le compose (`18-alpine`, `latest`…) qui pointe vers une **nouvelle image** | digest du registre ≠ digest local | sévérité calculée à partir du label `org.opencontainers.image.version` (local vs distant) |

Une stack est :

- **Mise à jour disponible** : bouton **Update Stack**.
- **Mise à jour majeure** : un tag flottant a changé de version majeure. Comme le pull ne peut pas être évité, le bouton devient **Forcer la mise à jour**, avec une confirmation.
- **Mise à jour manuelle** : une mise à jour existe, mais Drydock ne peut pas réécrire le tag (stack Git, image définie par une variable). Elle est indiquée, rien n'est appliqué.

### Registres pris en charge

Drydock interroge directement tout registre conforme à l'API OCI Distribution : Docker Hub, GHCR, lscr.io, Quay, GitLab, Gitea/Forgejo, Harbor, ACR, Artifact Registry, `registry:2`… Pour une image privée, ajoute ses identifiants dans `REGISTRY_AUTH` (`docker.io=user:jeton`). Portainer ne transmet pas les siens pour cette vérification. Pour lscr.io, ajoute aussi `REGISTRY_AUTH_REALMS=ghcr.io`.

Si Drydock ne peut pas joindre un registre (registre en HTTP simple, certificat auto-signé, registre accessible seulement depuis le serveur Docker), il demande le digest au Docker du serveur via Portainer. Dans ce cas :

- seules les nouvelles images derrière le même tag sont détectées, car le Docker du serveur ne sait pas lister les tags ;
- la version n'est pas comparée ;
- les images privées restent soumises à `REGISTRY_AUTH`.

En semver, une hausse de la version mineure sur une 0.x est considérée comme majeure. Les images qui ne publient pas leur version sont marquées « Inconnue », et une confirmation est demandée.

## Déroulé d'une mise à jour

1. Nouvelle analyse de la stack, puis réécriture des tags dans le compose (services activés uniquement).
2. Pull des seules images à mettre à jour, avant la maintenance : l'indisponibilité est plus courte, et un pull qui échoue ne modifie rien.
3. Les ressources Pangolin liées passent en maintenance (`maintenanceModeType: forced`). Celles qui y étaient déjà ne sont pas touchées.
4. `PUT /api/stacks/{id}` est appelé avec `pullImage: false` (les stacks Git passent par `git/redeploy`). Compose ne recrée que les conteneurs dont l'image a changé : les conteneurs désactivés gardent leur image.
5. Attente que tous les conteneurs du projet soient `running` et non `unhealthy`/`starting` sur 2 vérifications consécutives. Les conteneurs d'init terminés en `Exited (0)` sont acceptés.
6. La maintenance est retirée. En cas d'échec, elle reste active par défaut (`KEEP_MAINTENANCE_ON_FAILURE`).

## Lien stack ↔ ressource Pangolin

Les deux méthodes reposent sur les labels des conteneurs :

- **Automatique** : le label `url` (ex. `url: https://paperless.kareylo.fr`) est comparé au `fullDomain` des ressources Pangolin. Nécessite `PANGOLIN_ORG_ID`.
- **Explicite** : `drydock.pangolin.resource: "12,34"` (identifiants de ressources). Avec `PANGOLIN_ORG_ID`, seules les ressources de cette organisation sont acceptées : un autre identifiant est signalé en erreur et bloque la mise à jour de la stack.

## Activer ou désactiver les mises à jour

| Label sur le service | Effet |
|---|---|
| `drydock.enable: "false"` | Les mises à jour sont analysées et affichées, mais jamais appliquées. Le conteneur n'est pas recréé quand le reste de la stack est mis à jour. |
| `drydock.enable: "true"` | Mises à jour actives (utile en mode opt-in). |
| aucun | Actif par défaut. Avec `REQUIRE_ENABLE_LABEL=true`, seuls les services en `true` sont mis à jour. |
| `drydock.ignore: "true"` | Service exclu de l'analyse : rien n'est affiché. |

Une image partagée par plusieurs services est mise à jour seulement si **tous** ces services sont activés, car tirer l'image les modifie tous. Une stack dont toutes les mises à jour sont désactivées s'affiche « Mises à jour désactivées ».

## Configuration

| Variable | Défaut | Rôle |
|---|---|---|
| `PORTAINER_URL` | requis | ex. `https://portainer:9443` |
| `PORTAINER_API_KEY` (ou `_FILE`) | requis | clé API d'un utilisateur ayant accès aux stacks |
| `PORTAINER_CA_FILE` | — | certificat PEM à approuver pour Portainer : son autorité, ou son certificat auto-signé s'il n'est pas marqué `CA:TRUE` |
| `PORTAINER_INSECURE` | `false` | désactive la vérification du certificat (déconseillé : la clé API peut être interceptée). Un avertissement est loggé |
| `PANGOLIN_URL` | — | ex. `https://pangolin.example.com/integration/v1` |
| `PANGOLIN_API_KEY` (ou `_FILE`) | — | clé d'organisation, à créer dans *Organization > Management > API Keys*, avec les droits de lecture et de modification sur les ressources (pas une clé *Server Admin*). Elle n'est affichée qu'une fois |
| `PANGOLIN_ORG_ID` | — | active la correspondance automatique par domaine |
| `URL_LABEL` / `RESOURCE_LABEL` / `IGNORE_LABEL` / `ENABLE_LABEL` | `url` / `drydock.pangolin.resource` / `drydock.ignore` / `drydock.enable` | noms des labels |
| `REQUIRE_ENABLE_LABEL` | `false` | mode opt-in : seuls les services avec `drydock.enable: "true"` sont mis à jour |
| `HEALTH_TIMEOUT_SECS` | `300` | délai maximum pour que la stack redevienne healthy |
| `SCAN_INTERVAL_SECS` | `21600` | analyse périodique (`0` = désactivée) |
| `KEEP_MAINTENANCE_ON_FAILURE` | `true` | laisser la maintenance active si la stack ne redevient pas healthy |
| `REGISTRY_AUTH` (ou `_FILE`) | — | `docker.io=user:token,ghcr.io=user:token` (limites de requêtes, images privées) |
| `REGISTRY_AUTH_REALMS` | — | serveurs de jetons supplémentaires autorisés à recevoir ces identifiants, ex. `ghcr.io` pour `lscr.io`. Par défaut : le registre lui-même et les hôtes du même domaine (`auth.docker.io` pour Docker Hub). Les serveurs de jetons en `http://` sont toujours refusés |
| `REGISTRY_ALLOWLIST` | — | registres que Drydock a le droit d'interroger, ex. `docker.io,ghcr.io,lscr.io`. Vide : tous |
| `AUTH_MODE` | `basic` si `UI_BASIC_AUTH` est défini | `basic`, `proxy`, `oidc` ou `none`. Voir [Authentification](#authentification). Sans mode valide, Drydock refuse de démarrer |
| `ALLOWED_HOSTS` | — | noms d'hôte acceptés, ex. `drydock.example.com` (protection contre le DNS rebinding). Recommandé avec `AUTH_MODE=none` ou `proxy` |
| `MAINTENANCE_TITLE` / `MAINTENANCE_MESSAGE` | texte FR | contenu de la page de maintenance |
| `LISTEN` | `0.0.0.0:8080` | adresse d'écoute |
| `RUST_LOG` | `drydock=info` | niveau de logs |

## Authentification

L'interface et l'API sont toujours protégées. Choisis un mode avec `AUTH_MODE`.

### `basic` : mot de passe

| Variable | Rôle |
|---|---|
| `UI_BASIC_AUTH` (ou `_FILE`) | `user:motdepasse`, utilisateur non vide, mot de passe d'au moins 12 caractères |

### `proxy` : Pangolin SSO, Authelia en forward-auth…

Le proxy authentifie l'utilisateur, puis ajoute à chaque requête vers Drydock un en-tête contenant un secret partagé. Drydock refuse toute requête sans ce secret : un accès direct au conteneur, sans passer par le proxy, est donc bloqué.

| Variable | Défaut | Rôle |
|---|---|---|
| `PROXY_AUTH_SECRET` (ou `_FILE`) | requis | secret partagé, au moins 24 caractères (`openssl rand -base64 32`) |
| `PROXY_AUTH_SECRET_HEADER` | `X-Drydock-Proxy-Secret` | en-tête où le proxy place ce secret |
| `PROXY_USER_HEADER` | — | en-tête contenant l'utilisateur authentifié (ex. `Remote-User`). S'il est défini, il devient obligatoire |
| `PROXY_TRUSTED_IPS` | — | adresses ou réseaux autorisés à joindre Drydock, ex. `172.18.0.0/16` (réseau Docker du proxy). Recommandé |

- **Pangolin :** sur la ressource Drydock, active le SSO et l'option *forward identity headers*. Ajoute ensuite l'en-tête de requête personnalisé `X-Drydock-Proxy-Secret` avec le secret pour valeur (champ `requestHeaders` de la ressource, objets `{name, value}`). Pangolin transmet l'identité dans `Remote-User` (nom d'utilisateur), `Remote-Email`, `Remote-Name`, `Remote-Role` et `Remote-User-Id`. Badger supprime ces en-têtes s'ils viennent du client, donc ils ne peuvent pas être falsifiés en passant par Pangolin. Utilise `PROXY_USER_HEADER=Remote-User`. Pour `PROXY_TRUSTED_IPS`, indique le réseau Docker de Newt, car c'est Newt qui transmet les requêtes à Drydock.
- **Authelia + Traefik :** middleware `forwardAuth` vers Authelia (avec `authResponseHeaders: Remote-User`), plus un middleware `headers` dont `customRequestHeaders` ajoute le secret.

### `oidc` : n'importe quel fournisseur OpenID Connect (Authelia, Authentik, Keycloak…)

Drydock redirige vers le fournisseur (flux *authorization code* avec PKCE), puis ouvre une session : cookie `HttpOnly`, `SameSite=Lax`, et `Secure` en HTTPS.

| Variable | Défaut | Rôle |
|---|---|---|
| `OIDC_ISSUER` | requis | URL de l'émetteur, en `https://` |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` (ou `_FILE`) | requis | client confidentiel, authentifié par `client_secret_basic` |
| `OIDC_REDIRECT_URL` | requis | `https://drydock.example.com/auth/callback`, déclarée chez le fournisseur |
| `OIDC_SCOPES` | `openid profile email groups` | scopes demandés |
| `OIDC_ALLOWED_GROUPS` / `OIDC_ALLOWED_USERS` | — | groupes ou utilisateurs (nom, e-mail ou `sub`) autorisés. Sans eux, **tout utilisateur du fournisseur** peut mettre à jour les stacks (un avertissement est loggé) |
| `OIDC_GROUPS_CLAIM` | `groups` | claim qui contient les groupes |
| `OIDC_SESSION_HOURS` | `8` | durée maximale d'une session |

Exemple de client Authelia :

```yaml
identity_providers:
  oidc:
    clients:
      - client_id: drydock
        client_name: Drydock
        client_secret: '$pbkdf2-sha512$...'   # authelia crypto hash generate
        public: false
        authorization_policy: two_factor
        require_pkce: true
        pkce_challenge_method: S256
        redirect_uris: ['https://drydock.example.com/auth/callback']
        scopes: [openid, profile, email, groups]
        token_endpoint_auth_method: client_secret_basic
```

La déconnexion ferme la session Drydock. La session chez le fournisseur reste ouverte. Les sessions sont gardées en mémoire, donc un redémarrage de Drydock impose de se reconnecter. En mode `oidc`, l'API n'est utilisable que depuis l'interface (cookie de session).

### `none`

Aucune authentification. Ce mode est réservé au cas où quelque chose d'autre protège Drydock. Un avertissement est loggé. L'ancien `UI_AUTH_DISABLED=true` correspond à ce mode.

## Déploiement

Voir [compose.example.yaml](compose.example.yaml).

### Utilisateur et groupe (PUID / PGID)

Par défaut, Drydock tourne en `nobody` (65534:65534). Pour choisir l'utilisateur et le groupe, le compose d'exemple utilise `user: "${PUID:-65534}:${PGID:-65534}"` : définis `PUID` et `PGID` dans les variables d'environnement de la stack (Portainer, `.env`…). Docker applique lui-même ce choix au démarrage. L'image ne contient pas de shell et ne démarre jamais en root, donc rien n'est à changer de ce côté.

Les fichiers de secrets doivent être lisibles par cet utilisateur ou ce groupe :

```bash
sudo chown root:1000 /opt/drydock/secrets/*   # 1000 = PGID
sudo chmod 0440 /opt/drydock/secrets/*
```

Si un secret n'est pas lisible, Drydock s'arrête au démarrage avec `reading /run/secrets/<nom>` (permission refusée).

### Drydock ne se met jamais à jour lui-même

Redéployer sa propre stack arrêterait Drydock en pleine opération : la tâche serait perdue et la maintenance Pangolin resterait active. Drydock repère donc son propre conteneur, sans label à ajouter :

1. `DRYDOCK_CONTAINER_ID`, s'il est défini (ID complet ou préfixe d'au moins 12 caractères) ;
2. sinon, l'ID trouvé dans `/proc/self/mountinfo` (fichiers `hostname`/`resolv.conf` que Docker et Podman montent dans chaque conteneur) ;
3. sinon, le nom d'hôte, s'il vaut l'ID court (comportement par défaut sans `hostname:`).

La stack qui contient ce conteneur s'affiche « Stack de Drydock ». Ses mises à jour restent visibles, mais aucune n'est appliquée, et l'API refuse aussi de la mettre à jour. Le log de démarrage indique le conteneur détecté, ou un avertissement si la détection a échoué.

## Healthcheck (Docker et Podman)

L'image n'a pas de shell ni de `curl`. C'est le binaire qui sert de sonde : `/drydock healthcheck` appelle `/healthz` sur l'adresse de `LISTEN` et renvoie le code de sortie 0 ou 1.

La sonde est déclarée à deux endroits :

- **Dans le `Dockerfile` (`HEALTHCHECK`)** : c'est le healthcheck par défaut de l'image. Il est conservé si l'image est construite par Docker, ou par Podman/Buildah avec `--format docker`. Une image au format OCI (le format par défaut de Podman) l'ignore, car ce format ne prévoit pas de healthcheck.
- **Dans le compose (`healthcheck:`)** : il fonctionne quel que soit l'outil qui a construit l'image, avec Docker Compose, Portainer, `podman compose` et `podman-compose`. C'est la déclaration à garder en production.

Avec `podman run` sans compose : `--health-cmd '["/drydock","healthcheck"]' --health-interval 30s`. Côté Podman, les vérifications périodiques s'appuient sur des timers systemd. Sans systemd, lance `podman healthcheck run <conteneur>` à la main ou depuis un timer.

## Sécurité

- **TLS :** Drydock sert du HTTP simple. Il doit être publié derrière un proxy TLS (Pangolin), jamais exposé directement.
- **En-têtes :** chaque réponse porte une CSP stricte (seuls le script et le style intégrés à la page sont autorisés, par empreinte), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer` et `Cache-Control: no-store`.
- **Connexion :** un seul mauvais mot de passe est traité à la fois, avec 1 s d'attente. Les autres essais ratés reçoivent immédiatement `429` (`Retry-After: 1`), soit au plus environ un essai raté par seconde. Les échecs sont loggés, avec le nombre d'essais rejetés.
- **Clients lents :** une connexion qui n'envoie rien pendant 10 s est fermée, tout comme un client qui n'a pas fini d'envoyer ses en-têtes en 10 s. Drydock ne sert que HTTP/1 (HTTP/2 en clair est refusé). Au-delà de 256 connexions simultanées, les nouvelles sont refusées. À l'arrêt (SIGTERM), les requêtes en cours ont 10 s pour se terminer.
- **Clés en clair :** un `PORTAINER_URL` ou un `PANGOLIN_URL` en `http://` déclenche un avertissement au démarrage. À réserver à un réseau Docker isolé.
- **Registres :** les réponses sont plafonnées (4 Mio par manifeste, 16 Mio par liste de tags) et tout contenu demandé par digest est vérifié contre ce digest.
- **Conteneur :** [compose.example.yaml](compose.example.yaml) applique `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, des limites mémoire et PID, et passe les clés par des secrets (fichiers).
- **Image de build :** épinglée par digest dans le `Dockerfile`. Dependabot propose les mises à jour du digest.
- **Binaire auditable :** compilé avec `cargo auditable`, il embarque la liste de ses dépendances. Trivy et `cargo audit bin` peuvent donc vérifier le binaire livré, pas seulement `Cargo.lock`.
- **CI** ([.github/workflows/security.yml](.github/workflows/security.yml)) : à chaque push, à chaque pull request et chaque lundi, elle lance les tests, `cargo audit --deny warnings`, le build de l'image, un scan Trivy de l'image et un scan Trivy de la configuration. Une vulnérabilité HIGH ou CRITICAL fait échouer la CI. Les actions sont épinglées par SHA. [Dependabot](.github/dependabot.yml) met à jour chaque semaine les crates, l'image de build et les actions.

## Build

```bash
docker build -t drydock .
```

```bash
podman build --format docker -t drydock .
```

```bash
cargo test                      # tests unitaires
cargo test -- --ignored         # tests réseau contre Docker Hub / GHCR
cargo audit                     # CVE des dépendances (cargo install cargo-audit)
```

## API

- `GET /api/state` : rapports, état de l'analyse, 20 dernières tâches
- `POST /api/scan` : relancer l'analyse
- `POST /api/stacks/{id}/update` avec le corps `{"force": false}` : lancer une mise à jour
- `GET /api/jobs/{id}` : journal d'une tâche
- `GET /healthz` : sonde (sans authentification)

Drydock ne suit aucune redirection de Portainer ni de Pangolin, pour que leur clé API ne parte jamais vers un autre hôte. `PORTAINER_URL` et `PANGOLIN_URL` doivent donc être les URL finales.

Les requêtes `POST` venant d'un autre site (`Sec-Fetch-Site` ou `Origin` différent) sont refusées en `403`. Les clients hors navigateur (curl, scripts) ne sont pas concernés. `POST /api/stacks/{id}/update` exige `Content-Type: application/json`.
