==================================================================================
----------------------------------------------------------------------------------
8. Résumé ultra-court

Sur la machine proxy (A) :

Génère CA (myca.crt/myca.key) + cert serveur registry-1.docker.io.crt (CN + SAN) dans ~/certs-mitm.

Copie registry-1.docker.io.crt + .key dans le projet Rust.

Lance sudo target/debug/docker-mitm (écoute sur 0.0.0.0:443).

Ne PAS override registry-1.docker.io dans /etc/hosts de A.

Sur la machine Docker (B) :

/etc/hosts : IP_MACHINE_A registry-1.docker.io.

ca.crt = copie EXACTE de myca.crt dans /etc/docker/certs.d/registry-1.docker.io/ca.crt.

Pas de HTTP_PROXY, pas de registry-mirrors.

Redémarre Docker, vérifie docker info.

Test TLS avec openssl s_client → Verify return code: 0 (ok).

docker pull alpine → passe par ton MITM Rust.
----------------------------------------------------------------------------------
==================================================================================


MITM Docker Registry – Proxy Rust + CA custom

Ce guide explique comment :

faire tourner un proxy MITM TLS en Rust sur une machine proxy (Machine A),

forcer une machine Docker cliente (Machine B) à passer par ce proxy lorsqu’elle parle à registry-1.docker.io,

et utiliser une CA interne (MyRootCA) pour que TLS soit accepté.

🖥️ Machine A = proxy Rust / MITM
💻 Machine B = client Docker

Adapte les IP / chemins à ton environnement.

0. Prérequis
Machine A (proxy)

Rust + Cargo

OpenSSL (openssl)

Port 443/tcp accessible depuis la machine B

Le projet Rust avec le binaire docker-mitm (ton code).

Machine B (Docker client)

Docker (daemon + client)

Accès réseau à la machine A (port 443)

OpenSSL (pour tests avec openssl s_client)

1. Génération de la CA et du certificat serveur (Machine A)
1.1 Créer un dossier pour les certs
mkdir -p ~/certs-mitm
cd ~/certs-mitm

1.2 Générer la CA (MyRootCA)
# Clé privée de la CA
openssl genrsa -out myca.key 4096

# Certificat autosigné de la CA (valide 10 ans)
openssl req -x509 -new -key myca.key -sha256 -days 3650 -out myca.crt \
  -subj "/C=FR/ST=IDF/L=Paris/O=MyOrg/OU=Lab/CN=MyRootCA"


Vérification :

openssl x509 -in myca.crt -noout -subject
# subject=... CN = MyRootCA

1.3 Générer la clé + CSR pour registry-1.docker.io
# Clé privée du serveur MITM
openssl genrsa -out registry-1.docker.io.key 2048

# CSR avec CN = registry-1.docker.io
openssl req -new -key registry-1.docker.io.key -out registry-1.docker.io.csr \
  -subj "/C=FR/ST=IDF/L=Paris/O=MyOrg/OU=Lab/CN=registry-1.docker.io"

1.4 Ajouter le SAN (SubjectAltName)
printf "subjectAltName = DNS:registry-1.docker.io\n" > san.cnf

1.5 Signer le certificat serveur avec la CA
openssl x509 -req -in registry-1.docker.io.csr \
  -CA myca.crt -CAkey myca.key -CAcreateserial \
  -out registry-1.docker.io.crt -days 365 -sha256 \
  -extfile san.cnf


Vérification :

openssl x509 -in registry-1.docker.io.crt -noout -text | egrep "Subject:|DNS:"
# Subject: ... CN = registry-1.docker.io
# X509v3 Subject Alternative Name:
#     DNS:registry-1.docker.io

2. Brancher les certs dans le proxy Rust (Machine A)

On copie le cert serveur + la clé dans le dossier du projet Rust :

cp ~/certs-mitm/registry-1.docker.io.crt \
   ~/certs-mitm/registry-1.docker.io.key \
   ~/Desktop/MasterProject/DocDockGo/DockDockGo/


Dans ton main.rs, le chargement doit ressembler à :

let certs = load_certs("registry-1.docker.io.crt")?;
let key   = load_private_key("registry-1.docker.io.key")?;


(ce sont les fonctions qu’on a déjà écrites avec rustls_pemfile.)

3. Nettoyage du /etc/hosts sur Machine A

Sur Machine A, il ne faut PAS rediriger registry-1.docker.io vers toi-même.
Le proxy doit, lui, joindre le VRAI Docker Hub.

sudo nano /etc/hosts


➡️ Supprimer toute ligne du genre :

127.0.0.1   registry-1.docker.io


Puis vérifier :

getent hosts registry-1.docker.io
# → doit renvoyer une IP publique du registry Docker, pas 127.0.0.1

4. Lancer le proxy MITM (Machine A)

Depuis le projet Rust :

cd ~/Desktop/MasterProject/DocDockGo/DockDockGo

# Compilation
cargo build

# Lancement (port 443 -> nécessite sudo)
sudo target/debug/docker-mitm


Tu dois voir quelque chose comme :

✅ MITM Docker registry en écoute sur https://registry-1.docker.io:443


Option firewall (si ufw est actif) :

sudo ufw allow 443/tcp

5. Config de la machine Docker (Machine B)
5.1 Copier la CA depuis Machine A

Sur Machine A :

cd ~/certs-mitm
scp myca.crt camille@IP_MACHINE_B:/home/camille/myca.crt


(Remplace camille et IP_MACHINE_B par les bons.)

Sur Machine B :

ssh camille@IP_MACHINE_B

mkdir -p ~/certs-mitm
mv ~/myca.crt ~/certs-mitm/myca.crt

5.2 Installer la CA pour Docker

Docker cherche des CAs spécifiques par host dans :
/etc/docker/certs.d/<hostname>/ca.crt

sudo rm -rf /etc/docker/certs.d/registry-1.docker.io
sudo mkdir -p /etc/docker/certs.d/registry-1.docker.io
sudo cp ~/certs-mitm/myca.crt /etc/docker/certs.d/registry-1.docker.io/ca.crt

ls -l /etc/docker/certs.d/registry-1.docker.io
# → ca.crt

5.3 (Optionnel) Ajouter la CA au store système
sudo cp /etc/docker/certs.d/registry-1.docker.io/ca.crt /usr/local/share/ca-certificates/myrootca.crt
sudo update-ca-certificates

5.4 Rediriger registry-1.docker.io vers la machine A

Sur Machine B :

sudo nano /etc/hosts


Ajouter :

IP_MACHINE_A   registry-1.docker.io


Exemple :

172.16.254.10  registry-1.docker.io


Vérifier :

getent hosts registry-1.docker.io
# → 172.16.254.10 registry-1.docker.io

5.5 Nettoyer la config Docker (pas de proxy HTTP, pas de mirror)
/etc/docker/daemon.json
sudo nano /etc/docker/daemon.json


Contenu minimal (ou supprimer le fichier) :

{}

Supprimer d’éventuels HTTP proxy systemd
sudo ls /etc/systemd/system/docker.service.d
# si tu vois http-proxy.conf :
sudo rm /etc/systemd/system/docker.service.d/http-proxy.conf
sudo systemctl daemon-reload

5.6 Redémarrer Docker
sudo systemctl restart docker
docker info | egrep -i "HTTP Proxy|HTTPS Proxy|Registry Mirrors" -A2


Tu dois avoir les champs HTTP Proxy, HTTPS Proxy, Registry Mirrors vides.

6. Test TLS brut (Machine B → Machine A)

Avant de tester Docker, on vérifie la chaîne TLS :

openssl s_client -connect registry-1.docker.io:443 \
  -servername registry-1.docker.io \
  -CAfile /etc/docker/certs.d/registry-1.docker.io/ca.crt


À la fin, tu dois voir :

Verify return code: 0 (ok)


Si ce n’est pas 0 (ok), il y a encore un souci de CA / cert serveur.
Tant que ça, ce n’est pas bon, Docker ne passera pas.

7. Test avec Docker
7.1 S’assurer que le proxy tourne (Machine A)

Sur Machine A :

cd ~/Desktop/MasterProject/DocDockGo/DockDockGo
sudo target/debug/docker-mitm
# laisser tourner

7.2 Lancer un pull (Machine B)

Sur Machine B :

docker pull alpine