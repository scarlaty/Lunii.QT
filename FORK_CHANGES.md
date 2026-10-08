# Modifications du fork

Ce dépôt est un fork de [o-daneel/Lunii.QT](https://github.com/o-daneel/Lunii.QT)
publié sur [scarlaty/Lunii.QT](https://github.com/scarlaty/Lunii.QT) (remote `myfork`).

Base commune : `c8afe43` (*Merge pull request #52 from Sovxx/patch-1*), soit `origin/main` à la date du fork.
Toutes les modifications ci-dessous sont isolées dans des branches dédiées ; `main` reste identique à l'amont.
La branche `release/v3.1.5a1` les regroupe toutes (pre-release `v3.1.5a1`).

| Branche | État | Fichiers touchés | Sujet |
|---|---|---|---|
| `fix/flam-export-zip-timestamp-1980` | commité, poussé | `pkg/api/device_flam.py` | Crash export Flam (dates < 1980) |
| `fix/flam-export-shared-bt` | commité, poussé | `pkg/api/device_flam.py` | Export `.plain.pk` sans `bt` propre |
| `fix/ffmpeg-ssl-certifi` | commité, poussé | `pkg/ierWorker.py`, `requirements.txt` | Erreur SSL au téléchargement (Windows) |
| `docs/flam-usb-mode` | commité, poussé | `README.md`, `README_EN.md` | Prérequis « mode connexion USB » Flam |
| `feature/flam-plain-pk-carrier` | commité, **expérimental** (validé sur une Flam fw 1.15.14), basé sur `fix/flam-export-shared-bt` | `pkg/api/constants.py`, `pkg/api/device_flam.py`, `pkg/ierWorker.py`, `pkg/main_window.py`, `pkg/ui/main.ui`, `pkg/ui/main_ui.py` | Import `.plain.pk` via « carrier » |

---

## 1. Export Flam : timestamps antérieurs à 1980

Branche `fix/flam-export-zip-timestamp-1980` — commit `4d73e68`.

**Problème.** L'export d'une histoire depuis une Flam plantait avec :

```
ValueError: ZIP does not support timestamps before 1980
```

Certains fichiers du stockage Flam ont une date de modification antérieure au
01/01/1980, non représentable dans le format ZIP. `ZipFile.write()` appelle
`ZipInfo.from_file()` qui lève l'exception.

**Correctif** (`FlamDevice`, création de l'archive de backup) :
- construction manuelle du `ZipInfo`, avec date bornée à `1980-01-01 00:00:00` si nécessaire ;
- conservation des permissions (`external_attr`) ;
- copie en flux via `shutil.copyfileobj` (pas de chargement complet du fichier en mémoire).

## 2. Export Flam : réutilisation du `bt` d'une histoire sœur

Branche `fix/flam-export-shared-bt` — commit `356c2ef`.

**Problème.** Certaines histoires Flam n'ont pas leur propre fichier `bt`
(clé + IV de transchiffrement, 32 octets). « Exporter tout » retombait alors sur
un backup `.zip` chiffré au lieu d'un `.plain.pk` portable, alors que l'histoire
était déchiffrable.

**Constat.** Le `bt` n'est pas propre à une histoire : il est partagé par toutes
les histoires d'un même compte propriétaire, identifiables par un fichier `key`
identique.

**Correctif.** Nouvelle méthode `FlamDevice.__find_shared_bt(key, uuid)` :
parcourt les dossiers d'histoires visibles et cachées, cherche une histoire
sœur (même `key`, UUID différent) possédant un `bt`, et le réutilise.
Branchée dans `export_story()` comme repli avant le backup `.zip`. Si aucune
sœur n'a de `bt`, le comportement d'origine (backup `.zip`) est conservé.

## 3. Téléchargements : vérification SSL via `certifi`

Branche `fix/ffmpeg-ssl-certifi` — commit `836b919` — corrige l'issue amont #64.

**Problème.** `urllib.request.urlopen` utilise le contexte SSL par défaut qui,
sous Windows, ne lit pas le magasin de certificats système. Sur certaines
machines, le téléchargement de FFmpeg (et des autres fichiers) échoue avec :

```
[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1006)
```

**Correctif** (`pkg/ierWorker.py`) :
- nouvelle fonction `_ssl_context()` construisant un contexte à partir du bundle CA `certifi` ;
- passée aux deux appels `urlopen` (téléchargement FFmpeg et téléchargement générique) ;
- ajout de `certifi` dans `requirements.txt` (déjà présent indirectement via `requests`).

## 4. Documentation : mode connexion USB de la Flam

Branche `docs/flam-usb-mode` — commit `415ea63` — référence l'issue amont #67.

Contrairement aux Lunii v1/v2, la Flam ne se monte pas automatiquement : son
stockage n'est exposé que si le **mode connexion USB** est activé dans ses
paramètres. Sinon elle charge seulement et n'est détectée ni par l'OS ni par
Lunii.QT. Ajout d'une note « Prérequis » dans les sections Flam de `README.md`
et `README_EN.md`.

## 5. Import `.plain.pk` sur Flam via une histoire « carrier » (WIP)

Branche `feature/flam-plain-pk-carrier` — **expérimental**, validé sur une seule Flam (fw 1.15.14) avec une histoire homemade telmi2flam.

> Explication détaillée et comparaison avec o-daneel : [`IMPORT_CARRIER.md`](IMPORT_CARRIER.md)
> (constat sur une Flam réelle : §5.5 ; portée pour un autre utilisateur : §5.6).

**Contexte.** L'import `.plain.pk` d'origine (`import_flam_plain`) chiffre le
contenu avec une clé dérivée du SNU et écrit comme `key` le key-file du device.
Sur les firmwares Flam récents (constaté en 1.15.14), le firmware ne sait pas
déwrapper cette `key` : l'histoire importée s'affiche avec un titre illisible et
ne se lit pas. Seules les histoires conservant une `key` wrappée d'origine sont
lisibles.

**Principe.** Réutiliser le couple (`key`, `bt`) d'une histoire déjà lisible
sur le device (le « carrier ») : le contenu du `.plain.pk` est rechiffré avec le
`bt` du carrier et le fichier `key` du carrier est copié dans la nouvelle
histoire. Le firmware déchiffre alors la nouvelle histoire comme celles du
compte du carrier.

### Ajouts dans `pkg/api/device_flam.py` (`FlamDevice`)

- `_read_carrier_from_zip(zip_path)` *(staticmethod)* : extrait `bt` (32 o) et,
  si présent, `key` depuis un `.zip` Flam (zip Lunii ou backup contenant un
  `bt`). Retourne `{uuid_str, bt, key_file}` ou `None`.
- `_load_known_bts()` : lit les `bt` connus depuis `~/.lunii-qt/flam_known_bts.txt`
  (constante `FLAM_KNOWN_BTS`), **hors dépôt**. Aucun `bt` n'est codé en dur
  dans le source (cf. `IMPORT_CARRIER.md` §5.4).
- `_bt_decrypts_info(bt, info)` : vrai si le `bt` déchiffre (AES-CBC) le fichier
  `info` en UTF-8 valide, à ≥ 90 % imprimable (accents acceptés).
- `_detect_bt_from_info(info_data)` : essaie les `bt` du fichier ci-dessus puis
  ceux déjà détectés pendant la session. La clé dérivée du SNU est volontairement
  exclue : elle ne sert qu'aux histoires importées par Lunii.QT.
- `find_available_carriers()` : liste les histoires du device utilisables comme
  carrier. **Exclut** celles dont `key == self.keyfile` (importées par Lunii.QT,
  `key` illisible par le firmware récent). Source du `bt` : fichier `bt`, puis
  `__find_shared_bt()` (cf. §2), puis `_detect_bt_from_info()`. Chaque carrier
  est marqué `verified` si son `bt` déchiffre son `info`. Le résultat est trié :
  vérifiés d'abord, puis par source.
  Retourne `[{story, key_file, bt, source, verified}, …]`.
- `import_flam_plain_carrier(plain_pk_path, carrier)` : import proprement dit.
  - vérifie l'archive, lit l'UUID, refuse un doublon ;
  - rechiffre en AES-CBC avec le `bt` du carrier les fichiers `.lua` et `.plain` ;
    les autres (mp3, lif, version, mp3map) sont copiés tels quels ;
    `uuid`, métadonnées et vignette sont ignorés ;
  - gère l'abandon (nettoyage du dossier partiel) et la progression ;
  - écrit `key` = key-file du carrier, ajoute l'histoire et met à jour l'index.

### Ajouts côté worker et UI

- `pkg/ierWorker.py` : nouvelle action `ACTION_IMPORT_CARRIER = 13`, paramètre
  `carrier` dans le constructeur, tâche `_task_import_carrier()` (logs, durée,
  rafraîchissement).
- `pkg/ui/main.ui` / `pkg/ui/main_ui.py` : action de menu
  `actionImportCarrier` « Import plain.pk (Carrier) » (icône import), ajoutée au
  menu *Stories* après « Import ».
- `pkg/main_window.py` :
  - action activée uniquement si le device sélectionné est une Flam (`FLAM_V1`) ;
  - `ts_import_carrier()` : choix du `.plain.pk`, puis choix optionnel d'un
    `.zip` carrier (refusé si c'est un import Lunii.QT) ; si annulé, scan du
    device et, s'il y a plusieurs carriers, liste de choix (`QInputDialog`)
    avec le meilleur en premier ;
  - `worker_launch()` accepte un paramètre `carrier`.

### Limites / reste à faire

- Les nouvelles chaînes UI ne sont pas encore traduites (`locales/`).
- Validé sur une seule Flam (fw 1.15.14) ; autres firmwares et appareils : appel à testeurs (`IMPORT_CARRIER.md` §9).
- Sauvegarder `~/.lunii-qt/flam_known_bts.txt` : c'est le seul endroit où sont conservés les `bt` connus.
- L'histoire importée dépend du compte du carrier : la supprimer du compte
  d'origine ou réinitialiser le device peut la rendre illisible.
- Conserver systématiquement les `.zip` de backup d'origine : un `.plain.pk`
  (clé retirée) ne permet pas de restaurer une histoire à l'identique.
- `err.txt` (vide, non suivi) traîne à la racine du worktree.
