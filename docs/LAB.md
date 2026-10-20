# Lumen Lab : vie privée, pentest, terminal Linux, installeur d'APK

Ajouté à Lumen OS 2. Un nouveau tiroir **Lab** (violet) sur l'écran d'accueil contient trois apps :
**Terminal**, **Packages**, **Shield**.

## Démarrage

```sh
./run.sh        # reconstruit (le noyau est reconfiguré : 1er build long), crée storage.img (4 Go, ext4), lance le pont
```

* `storage.img` est monté sur `/data` dans le téléphone (home du terminal, APK installés, téléchargements).
  Si le formatage échoue, `/data` vit en RAM et le téléphone démarre quand même.
* Dépose des `.apk` dans `./apks/` sur le Mac : l'app Packages les liste et les télécharge via le pont.

## Terminal

Vrai shell Linux (busybox ash, root) sur un pty, émulateur VT100/xterm maison (couleurs 256/truecolor,
écran alterné pour `vi`, défilement tactile, clavier avec Esc/Tab/Ctrl/flèches, taille de police A-/A+).
La session continue en arrière-plan quand on quitte l'app. Environ 270 commandes busybox (`vi`, `nc`, `wget`,
`ping`, `ip`, `ps`, `top`...) plus cinq outils intégrés au binaire `/init` :

| commande | rôle |
|---|---|
| `apkinfo f.apk` | analyse statique : manifeste, permissions, signataire, trackers, secrets en dur, score de risque |
| `pm install [-f] f.apk` / `uninstall` / `list` / `info` / `path` | gestion des paquets dans `/data/app` |
| `scan [-p ports] [-b] hôte` / `scan -s 10.0.2.0/24` | scanner de ports TCP (bannières avec `-b`) et balayage d'hôtes |
| `sniff [-i if] [-c n] [-w cap.pcap] [-v]` | capture de paquets (ARP/IP/TCP/UDP/DNS/HTTP), export pcap lisible par Wireshark |
| `fetch [-o fichier] URL` | GET HTTPS avec la pile TLS de Lumen (le `wget` busybox n'a pas de TLS) |

Ne scanne que ce qui t'appartient ou ce que tu es autorisé à tester.

## Packages (installeur d'APK)

Liste les APK présents (`/data/Download`, `/data/apks`), les paquets installés et ceux du pont Mac.
Toucher un APK lance l'audit : risque 0-100, constats classés (debuggable, allowBackup, composants exportés,
TLS désactivé, clés API en dur, URL http://, WebView JS bridge...), permissions triées par gravité,
SDK de pistage connus (Firebase, AppsFlyer, AdMob...), signataire + empreinte SHA-256, hash du fichier.
Installer copie l'APK dans `/data/app/<paquet>/` et extrait les `.so` de la meilleure ABI.
**Une mise à jour signée avec une autre clé est refusée** (APK repackagé), sauf confirmation explicite.

## Shield (vie privée)

* **Blocage de trackers par DNS** : ~110 domaines intégrés + `/data/shield/custom.txt` (domaines ou format hosts,
  rechargé à chaud). Compteur et derniers domaines bloqués dans l'app.
* **DNS privé** au choix (Quad9, Cloudflare, Mullvad) ; le DNS actif est aussi écrit dans `/etc/resolv.conf`.
* **MAC aléatoire** à chaque démarrage, aucun nom d'hôte envoyé en DHCP.
* **HTTPS-only** dans le navigateur (http:// est promu en https://, sauf adresses locales).
* **PIN d'écran de verrouillage** (4-12 chiffres, SHA-256 salé itéré, 5 essais ratés = blocage croissant, compteur
  conservé après redémarrage).
* **Météo de l'écran de verrouillage désactivée par défaut**, et la requête de test vers example.com qui partait
  à chaque connexion a été supprimée : plus aucune requête réseau non demandée.
* Panneau d'exposition : ports TCP en écoute, MAC et DNS utilisés.

## Limites (à lire)

* **Les APK ne s'exécutent pas.** Lumen n'a pas de runtime Android (ART, framework, binder). Packages analyse,
  vérifie et stocke ; le bouton *Open* appelle `/system/bin/apk-runtime <paquet> <activité>` s'il existe
  (point d'accroche pour un futur Waydroid/Anbox), sinon il l'explique.
* La signature est lue (empreinte du certificat) mais **pas vérifiée cryptographiquement** contre le contenu.
* Le PIN verrouille l'interface ; **le disque n'est pas chiffré**. Le terminal est root.
* DNS en UDP clair (pas de DoT/DoH). Le blocage ne couvre que les requêtes passant par le résolveur de Lumen.
* Le nom de l'app d'un APK est le nom de paquet quand le libellé est une ressource (resources.arsc non lu).

## Vérifié / non vérifié

Vérifié sur machine hôte (x86, ASan/UBSan) : analyse d'un vrai APK comparée à androguard (paquet, version,
SDK, permissions, activité principale, certificat et empreinte identiques), installation, refus de signature
différente, 150 fichiers corrompus sans plantage, émulateur VT sur séquences connues, shell busybox réel via pty
(édition, flèches, `vi`, `top`, `stty size`), scanner de ports, sniffer + pcap, pont HTTP (traversée de chemin
refusée), PIN et verrouillage, blocklist, rendu des écrans en captures (`screenshots/lab-*.png`), et édition de
liens complète du projet.
**Non vérifié : compilation du noyau et démarrage dans QEMU** (pas de source noyau accessible ici). Les nouvelles
options noyau (`UNIX98_PTYS`, `EXT4_FS`...) sont dans `kernel/lumen.config` ; le script de build signale celles qui
ne s'appliquent pas. Les tests `test/e2e.py` ont leurs coordonnées mises à jour pour le tiroir Lab mais n'ont pas
été relancés.
