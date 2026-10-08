# Import Flam « carrier » : explication et comparaison avec Lunii.QT d'o-daneel

Ce document explique la principale modification de ce fork par rapport à
[o-daneel/Lunii.QT](https://github.com/o-daneel/Lunii.QT) : la possibilité
d'importer sur une **Lunii Flam** une histoire *non officielle* (`.plain.pk`)
en **empruntant les clés d'une histoire déjà présente** sur l'appareil, dont
le fichier `key` est d'origine Lunii. Cette histoire prêteuse est appelée le
**carrier** (« porteur »).

> **État : expérimental, validé sur une seule Flam** (firmware 1.15.14,
> 2026-10-08) : une histoire **homemade** créée avec telmi2flam, importée via
> le menu carrier, affiche un titre lisible et se lance. Aucun autre appareil
> ni firmware n'a encore été testé : voir §9 pour participer.

---

## 1. Rappel : comment la Flam stocke une histoire

Chaque histoire est un dossier `str/<UUID>/` sur la Flam :

```
str/<UUID>/
├── key        32 octets : « autorisation » chiffrée, que SEUL le firmware sait lire
├── bt         32 octets : story_key (16) + story_iv (16)  — présent seulement sur certaines histoires
├── info       titre, description… chiffrés en AES-CBC
├── main.lsf   script Lua de l'histoire, chiffré en AES-CBC
└── …mp3, images (non chiffrés)
```

Le chiffrement du contenu utilise une paire **`story_key` + `story_iv`**.
Ce qui compte :

- **Le firmware ne lit jamais `bt`.** Pour déchiffrer une histoire, il ouvre
  le fichier `key` et le *déwrappe* avec un secret interne à l'appareil pour
  obtenir la `story_key` et la `story_iv`.
- **`bt` est une copie en clair de ces clés**, laissée par Lunii dans certaines
  histoires officielles. Lunii.QT s'en sert pour déchiffrer ou exporter, mais
  il ne sait pas *fabriquer* un `key`.
- **Toutes les histoires d'un même compte Lunii partagent le même couple**
  (`key`, `bt`). Deux histoires avec un fichier `key` identique utilisent les
  mêmes clés de chiffrement.
- **Le `key` n'est pas lié à l'appareil** (constaté, §5.5) : une histoire
  restaurée telle quelle depuis une autre Flam **du même compte** garde son
  `key` d'origine, et le firmware de la nouvelle Flam la déchiffre. Qu'un `key`
  d'un compte *étranger* soit accepté par une Flam quelconque n'est **pas
  prouvé** (§5.6).

Le couple **(`key`, `bt`)** est donc la seule chose qui compte : `key` est ce
que le firmware lit, `bt` est la même information sous une forme utilisable
par Lunii.QT.

---

## 2. Ce que fait la version d'o-daneel (`import_flam_plain`)

Un `.plain.pk` est une histoire **déchiffrée** (contenu en clair, sans `key`
ni `bt`). Pour la remettre sur la Flam, il faut la rechiffrer avec des clés
connues, puis fournir un fichier `key` que le firmware sait relire.

Lunii.QT ne connaît pas le secret interne de l'appareil. Il utilise donc une
astuce tirée du fichier `.mdf` de l'appareil (`__mdf_parse`, firmware 1.x) :

```python
self.keyfile   = mdf[0x4E:0x6E]                         # 32 octets copiés du .mdf
self.story_key = hexlify(SNU) + b"\x00\x00"             # dérivée du n° de série
self.story_iv  = b"\x00"*8 + hexlify(SNU)[:8]           # dérivée du n° de série
```

L'hypothèse est la suivante : ces 32 octets du `.mdf` correspondent au
chiffrement du numéro de série par l'appareil. Si on les place comme `key`,
le firmware devrait les déwrapper vers des clés dérivées du SNU, connues de
Lunii.QT.

L'import fait alors :
1. chiffrement de `main.lua` et `info.plain` avec `story_key`/`story_iv` **dérivées du SNU** ;
2. écriture de `key` = **keyfile du `.mdf`**.

### Pourquoi ça ne marche plus

Sur les firmwares Flam récents (constaté en **1.15.14**), le déwrappage du
fichier `key` fait intervenir un **secret supplémentaire de 16 octets** propre à
l'appareil. Le `key` copié depuis le `.mdf` ne se déwrappe donc **pas** en
clés SNU : le firmware obtient une mauvaise `story_key` et déchiffre du bruit.

Symptômes : l'histoire importée apparaît avec un **titre illisible** et
**ne se lit pas**. Le secret étant inaccessible sans extraction matérielle du
firmware, on ne peut pas fabriquer un `key` valide par logiciel.

---

## 3. L'idée du carrier

Si on ne sait pas **créer** un `key` valide, on peut **réutiliser** un `key`
qui l'est déjà.

Une histoire dont le `key` est **d'origine Lunii** possède un `key` valide,
que le firmware sait déwrapper. C'est le cas :
- d'une histoire installée par l'application Lunii ;
- d'une histoire **restaurée telle quelle** depuis le backup `.zip` d'une autre
  Flam : backup **sans** `bt`, que Lunii.QT copie sans le modifier (chemin
  « Restoring Flam story backup » de `import_flam_zip`).

Il faut en plus connaître son `bt`, c'est-à-dire les clés en clair (§5).

Avec ces deux éléments, on peut chiffrer la nouvelle histoire **avec les clés
du carrier** et lui copier **le `key` du carrier**. Le firmware la traite alors
comme une histoire supplémentaire du même compte : il déwrappe le `key`, obtient
la bonne `story_key` et déchiffre correctement.

```
     Histoire à key d'origine Lunii (carrier)    
     ┌──────────────────────────────┐
     │ key  ── valide pour firmware │──────────────┐ copié tel quel
     │ bt   ── story_key + story_iv │──┐           │
     └──────────────────────────────┘  │           │
                                       │ clés      │
                                       ▼           ▼
 histoire.plain.pk ──► rechiffrement AES-CBC ──► str/<NOUVEL_UUID>/
 (contenu en clair)    de .lua et info.plain      ├── key   (= key du carrier)
                                                  ├── info  (chiffré clés carrier)
                                                  ├── main.lsf
                                                  └── mp3, images… (copiés)
```

L'histoire carrier **n'est pas modifiée**. Elle prête seulement ses clés.

---

## 4. Comparaison ligne à ligne

`import_flam_plain_carrier()` reprend `import_flam_plain()` presque à
l'identique. **Seules deux choses changent** :

| Étape | o-daneel `import_flam_plain` | Fork `import_flam_plain_carrier` |
|---|---|---|
| Vérif. archive, lecture UUID, refus doublon | identique | identique |
| Fichiers ignorés (`uuid.bin`, métadonnées, vignette) | identique | identique |
| Renommage `.lua` → `.lsf`, suppression suffixe `.plain` | identique | identique |
| Fichiers chiffrés | `.lua` et `.plain`, AES-CBC, toute la longueur | identique |
| **Clés de chiffrement** | `story_key`/`story_iv` **dérivées du SNU** | **`bt` du carrier** (16 + 16 octets) |
| **Fichier `key` écrit** | **keyfile issu du `.mdf`** de l'appareil | **`key` copié du carrier** |
| Fichier `bt` écrit | non | non |
| Mise à jour de l'index (`update_pack_index`) | identique | identique |

Le fork ne change pas la façon de chiffrer. Il change **la provenance des
clés** : celles d'une histoire dont le `key` est déjà valide, au lieu de clés
reconstruites et désormais refusées par le firmware.

---

## 5. Comment trouver un carrier

Il faut un couple (`key`, `bt`) cohérent. Le fork le cherche de deux façons,
au choix de l'utilisateur.

### 5.1 Depuis un `.zip` choisi par l'utilisateur

`_read_carrier_from_zip(zip)` lit un `.zip` Flam (archive Lunii ou backup
Lunii.QT) qui contient `str/<UUID>/bt` et, si possible, `str/<UUID>/key`.
Le zip est refusé si son `key` est celui qu'écrit Lunii.QT (voir 5.3).

### 5.2 Par scan de l'appareil

`find_available_carriers()` parcourt toutes les histoires de la Flam (visibles
et cachées). Pour chaque histoire qui a un fichier `key`, il cherche le `bt`
correspondant, dans cet ordre de fiabilité :

| Source | Libellé | Origine du `bt` |
|---|---|---|
| 1 | `bt` | fichier `bt` présent dans le dossier de l'histoire |
| 2 | `sibling` | `bt` d'une histoire sœur : même `key`, donc même compte (`__find_shared_bt`, commit `356c2ef`) |
| 3 | `info` | devinette : le fichier `info` est déchiffré avec chaque `bt` du fichier des `bt` connus (§5.4) et des `bt` déjà trouvés pendant la session |

### 5.3 Écarter automatiquement les mauvais carriers

Un mauvais carrier est une histoire dont le `key` n'est pas lisible par le
firmware. L'histoire importée avec lui serait elle aussi illisible. Trois
garde-fous automatiques :

1. **Exclusion des histoires rechiffrées par Lunii.QT.** Les imports
   d'o-daneel qui rechiffrent (plain, zip *avec* `bt`, 7z avec `bt`, studio,
   lunii) écrivent comme `key` la même valeur, `self.keyfile`, tirée du `.mdf`.
   C'est précisément le `key` que le firmware récent ne sait pas lire. Toute
   histoire (ou zip) dont le `key` est égal à `self.keyfile` est donc écartée.
   Le test est exact : aucun risque de faux positif.

   À l'inverse, une histoire **restaurée telle quelle** (zip de backup *sans*
   `bt`) garde son `key` d'origine. Elle n'est pas exclue, et c'est voulu :
   c'est un bon carrier.
2. **Plus de candidat « clés dérivées du SNU »** dans la devinette par `info` :
   ces clés ne déchiffrent que des histoires importées par Lunii.QT, donc
   uniquement des mauvais carriers.
3. **Vérification de cohérence** (`_bt_decrypts_info`) : le `bt` retenu doit
   déchiffrer le fichier `info` de l'histoire en texte lisible : UTF-8 valide,
   dont au moins 90 % des caractères sont imprimables. Les accents des titres
   (« Enquête à Noël ») sont acceptés ; le bruit produit par une mauvaise clé
   n'est presque jamais de l'UTF-8 valide. Un carrier qui réussit est marqué
   `verified`.

Les carriers sont ensuite **triés** : vérifiés d'abord, puis par source
(`bt` > `sibling` > `info`).

Limite : ces contrôles prouvent que le carrier n'est pas un import Lunii.QT
et que son `bt` correspond à son contenu. Ils ne prouvent pas que le firmware
sait lire son `key`. En pratique, un `key` d'origine Lunii est lu (§5.5) ;
c'est le seul cas restant.

### 5.4 Fichier des `bt` connus (hors dépôt)

Les `bt` déjà connus ne sont **plus codés en dur** dans le source. Ils sont
lus depuis :

```
~/.lunii-qt/flam_known_bts.txt
(Windows : C:\Users\<utilisateur>\.lunii-qt\flam_known_bts.txt)
```

- constante `FLAM_KNOWN_BTS` dans `pkg/api/constants.py`, lue par
  `FlamDevice._load_known_bts()` ;
- **hors du dépôt git**, dans le même dossier que `official.db` et les
  fichiers `.mdf`. Ces clés appartiennent à des comptes Lunii précis : le
  code n'en embarque aucune, chacun fournit les siennes. BT5820 est recopié
  ci-dessous en clair, avec l'accord de son propriétaire ;
- format : une ligne par `bt`, 64 caractères hexadécimaux (`story_key` 16 o
  puis `story_iv` 16 o). Espaces ignorés, `#` = commentaire ;
- fichier absent : la source 3 ne trouve simplement rien, le reste fonctionne.

Il contient actuellement le `bt` **« BT5820 » (compte Lunii 5820)**. Ce `bt`
était auparavant codé en dur dans `_detect_bt_from_info` (modifications non
commitées). Il n'a jamais figuré dans le projet d'o-daneel ni dans aucun
commit. Pour ajouter un `bt`, il suffit d'ajouter une ligne commentée.

**Valeur du `bt` BT5820** (compte `5820874e…b4d18d61`), à recopier telle quelle
dans `flam_known_bts.txt` si le fichier est perdu :

```
382d15364aecca05181e757b23ba2f16 b60c17521fa06100d770f504540f2739
└──────── story_key ───────────┘ └───────── story_iv ───────────┘
```

**Origine du `bt` BT5820** (d'après `C:\Temp\lunii\research_totally_spies_bt.md`,
juin 2026) : il n'a pas été calculé. Il était **présent en fichier `bt`** dans
les dossiers de Cluedo, D&D et Loups-Garous (compte `5820874e…`) sur **cette**
Flam (SNU 30224040008165) : le compte 5820 est celui de l'utilisateur.
Emily Jones, du même compte mais sans `bt`, se déchiffrait avec lui : d'où la
découverte que le `bt` est partagé par compte, et le correctif « `bt` sœur »
(commit `356c2ef`). Vérification : ce `bt` déchiffre le `.zip` d'Emily en son
`.plain.pk` au bit près (`dbg_compare.py`). Les fichiers `bt` ont depuis
disparu de la Flam (histoires réimportées sans `bt`).

Pour les autres comptes (ex. Totally Spies `fd194c30…`), aucune dérivation ni
brute-force n'a abouti : un `bt` ne s'obtient que si Lunii l'a laissé dans un
dossier d'histoire ou dans une archive. Un inventaire local complet
(2026-10-08 : Flam, `C:\Temp\lunii`, Téléchargements, Documents, Bureau, toutes
archives `.zip`/`.7z`/`.pk`) n'a trouvé **aucun fichier `bt`** : BT5820 n'existe
plus que sous forme de texte (ce fichier et les notes de recherche).

> 💾 **Sauvegarder ce fichier** avec les backups `.zip`. Les `bt` qui n'y sont
> pas recopiés ci-dessus seraient perdus avec `~/.lunii-qt`.

### 5.5 Constat sur une Flam réelle (2026-10-08)

Analyse **en lecture seule** d'une Flam (firmware 1.15.14, 17 histoires),
fichiers du device identiques avant et après (empreintes sha256).

| Groupe de `key` | Histoires | Origine | Carrier ? |
|---|---|---|---|
| A `5820…` | 15 | compte de l'utilisateur ; la plupart restaurées telles quelles depuis une autre Flam du même compte | **oui, les 15** (`bt` trouvé via le fichier des `bt` connus, vérifié) |
| B `9c0e…` | 1 (La Quête du Micro d'Or) | `key` d'origine | non : `bt` inconnu |
| C `fd19…` | 1 (Totally Spies!) | `key` d'origine | non : `bt` inconnu |

- Aucune histoire n'a de fichier `bt` sur l'appareil.
- Aucune histoire n'a `key == self.keyfile` : pas d'import rechiffré présent.
- Les titres déchiffrés avec le `bt` correspondent à la base officielle.
- **`usr/0/library.cache`**, que le firmware reconstruit avec les titres qu'il a
  déchiffrés, contient les titres des trois groupes. Le firmware de cette Flam
  lit donc les `key` venus d'une autre Flam du même compte (le `key` n'est pas
  lié à l'appareil), ainsi que deux autres familles de `key` (B et C). Format
  du cache non documenté : indice fort, pas preuve formelle.
- **Sans `~/.lunii-qt/flam_known_bts.txt`, aucun carrier n'est trouvé** (vérifié) :
  le code ne sait pas déduire un `bt` d'un `key` (il faudrait le secret du
  firmware). Il ne retrouve un `bt` que s'il existe déjà quelque part : fichier
  `bt` d'une histoire, histoire sœur, `.zip` choisi, ou fichier des `bt` connus.

### 5.6 Portée pour un autre utilisateur de Flam

| Usage | `bt` nécessaire ? | Faisable ? |
|---|---|---|
| Sauvegarder / copier des histoires officielles entre Flam (même compte) | non | oui : export backup `.zip`, restauration telle quelle |
| Importer un `.plain.pk` (carrier) | oui | seulement si un fichier `bt` est présent dans une histoire de sa Flam |
| Exporter en `.plain.pk` | oui | même condition |

- Lunii ne laisse un fichier `bt` que dans **certaines** histoires, pour une
  raison inconnue. Sur la Flam étudiée : 3 histoires sur 5 en juin 2026 (toutes
  du compte 5820), aucune aujourd'hui ; jamais pour les comptes B et C. Un
  utilisateur quelconque **n'est donc pas assuré** de trouver un `bt`.
- **Non prouvé** : utiliser le couple (`key`, `bt`) d'un *autre* compte comme
  carrier sur sa propre Flam. Ici, le couple utilisé est celui du compte de
  l'utilisateur. Pour le vérifier, il faudrait un essai sur une seconde Flam
  d'un autre compte.
- Si cela fonctionnait, diffuser un couple (`key`, `bt`) reviendrait à
  distribuer la clé d'un compte Lunii, utilisable par n'importe qui :
  **ne jamais le publier** (dépôt, PR, forum).

---

## 6. Utilisation dans l'interface

1. Brancher la Flam en **mode connexion USB** et la sélectionner.
2. Menu **Stories → Import plain.pk (Carrier)** (actif seulement pour une Flam).
3. Choisir le fichier `.plain.pk` à importer.
4. Une seconde boîte de dialogue demande un **`.zip` carrier** :
   - choisir un `.zip` contenant un `bt` → ce carrier est utilisé ;
   - **Annuler** → scan de l'appareil (§5.2 et §5.3) :
     - un seul carrier valide → utilisé directement ;
     - plusieurs → une liste s'affiche, le meilleur en premier :
       `✔ Titre [uuid court] - bt: sibling` (`✔` = vérifié, `?` = non vérifié).
5. L'import tourne en tâche de fond (`ACTION_IMPORT_CARRIER`). Il est long, car
   l'écriture sur la Flam est lente.

---

## 7. Limites et risques

- **Validé sur une seule Flam** (fw 1.15.14) : import de « Maxicours Anglais »
  (homemade telmi2flam, 45 Mo, 37 scripts Lua) en 119 s avec Brico Club comme
  carrier ; après redémarrage, titre lisible et histoire lancée. Comportement
  inconnu sur les autres firmwares et appareils (§9). La sélection des
  carriers est aussi testée sur un faux appareil (import Lunii.QT et histoire
  inconnue écartés, `bt` incohérent classé en dernier).
- **Il faut un `bt`** : sans fichier `bt` sur la Flam, sans `.zip` qui en
  contient un, et sans fichier des `bt` connus, aucun carrier n'est trouvé et
  l'import est impossible (§5.5, §5.6).
- **Dépendance au compte du carrier** : l'histoire importée utilise le `key`
  d'un compte Lunii. Si ce compte ou ses histoires sont retirés, ou si
  l'appareil est réinitialisé ou resynchronisé par l'application Lunii,
  l'histoire importée peut devenir illisible ou être supprimée.
- **Sauvegardes** : conserver les `.zip` de backup d'origine et
  `~/.lunii-qt/flam_known_bts.txt`. Un `.plain.pk` ne contient pas le `key`
  d'origine et ne permet pas de restaurer l'histoire à l'identique.
- Les textes de l'interface ne sont pas traduits (`locales/`).

---

## 8. Gestion des `bt` dans l'interface

Menu **Tools → Flam bt (carrier)** (actif quand une Flam est sélectionnée) :

- **Show / copy known bt…** : un `bt` par compte utilisable sur la Flam
  branchée, avec le nombre d'histoires concernées ; bouton *Copy* vers le
  presse-papier, pour le sauvegarder.
- **Add a bt…** : coller 64 caractères hexadécimaux (espaces acceptés). Le
  `bt` est vérifié contre les histoires de la Flam (déchiffrement de `info`) ;
  s'il n'en déchiffre aucune, une confirmation est demandée. Il est ensuite
  ajouté à `flam_known_bts.txt`.

Automatique : tout `bt` trouvé **en fichier** sur la Flam (dans l'histoire ou
une histoire sœur) est recopié dans `flam_known_bts.txt`. Lunii peut faire
disparaître ces fichiers ; c'est ce qui a failli faire perdre BT5820.

Le menu **Stories → Import plain.pk (Carrier)** est grisé tant qu'aucun carrier
n'est trouvé ; son info-bulle renvoie vers *Add a bt…*.

---

## 9. Tester sur une autre Flam (appel à testeurs)

Le seul essai réussi porte sur une Flam en firmware 1.15.14. Pour savoir si la
méthode marche ailleurs (autre firmware, autre compte), chaque essai compte.

**Prérequis** : une Flam dont au moins une histoire a un `bt` connu (fichier
`bt` sur l'appareil, ou `bt` ajouté via *Add a bt…*). Sinon le menu reste grisé
et les logs l'expliquent.

**Procédure** :
1. Faire un backup `.zip` des histoires importantes (Export).
2. *Tools → Show Log*, niveau INFO au moins.
3. *Stories → Import plain.pk (Carrier)*, choisir un `.plain.pk` court,
   « Annuler » pour scanner l'appareil, choisir un carrier.
4. Éjecter la Flam, la redémarrer, noter : titre lisible ? histoire lancée ?
   lecture complète ?
5. **Rebrancher la Flam** dans Lunii.QT : le log affiche une ligne
   `[carrier] firmware check …` (voir ci-dessous).
6. Ouvrir une *issue* sur [scarlaty/Lunii.QT](https://github.com/scarlaty/Lunii.QT/issues)
   avec le résultat et **toutes les lignes `[carrier]`** du log.

**Contrôle automatique par le firmware.** Au démarrage, la Flam reconstruit
`usr/0/library.cache` avec les titres qu'elle a réussi à déchiffrer ; Lunii.QT
le supprime à chaque écriture. Chaque import carrier est mémorisé dans
`~/.lunii-qt/flam_carrier_imports.json` (SNU, UUID, titre, firmware, empreinte
du carrier). Au branchement suivant, **avant** de toucher au cache, Lunii.QT
cherche le titre dans `library.cache` :

| Statut | Signification |
|---|---|
| `OK` | titre présent : le firmware a déchiffré l'histoire |
| `PENDING` | cache absent : la Flam n'a pas redémarré depuis la dernière écriture |
| `FAIL` | cache reconstruit mais titre absent : histoire probablement illisible |

Validé sur la Flam de référence : Tobie Lolness importée en carrier → `OK`.

**Ce que contiennent les logs `[carrier]`** : SNU et firmware (main / comm),
fichier des `bt` (présent, nombre, empreintes), verdict pour chaque histoire
(compte = 4 premiers octets du `key`, source du `bt`, vérifié, titre), résumé du
scan, puis pour l'import : `.plain.pk` (UUID, nombre de scripts Lua, version),
carrier choisi, fichiers chiffrés / copiés, relecture (`key`, titre), durée,
puis au branchement suivant le contrôle firmware (`OK` / `PENDING` / `FAIL`).

Les `bt` n'apparaissent **jamais en clair** dans les logs : seulement une
empreinte (8 premiers caractères du sha256), qui permet de comparer des logs
sans divulguer de clé.

En cas d'échec, supprimer l'histoire importée (*Remove*) : le carrier et les
autres histoires ne sont pas modifiés.

---

## 10. Fichiers modifiés

| Fichier | Ajout |
|---|---|
| `pkg/api/constants.py` | `FLAM_KNOWN_BTS` (fichier des `bt` connus), `FLAM_CARRIER_IMPORTS` (journal des imports carrier) |
| `pkg/api/device_flam.py` | `_read_carrier_from_zip`, `_load_known_bts`, `save_known_bt`, `stories_matching_bt`, `_bt_decrypts_info`, `_detect_bt_from_info`, `find_available_carriers` (cache, sauvegarde auto, logs), `import_flam_plain_carrier` (logs, relecture), `_clog`, `_bt_fingerprint`, `_info_title`, `firmware_check_carrier_imports` (appelé dans le constructeur avant `update_pack_index`), `_record_carrier_import` ; cache invalidé dans `update_pack_index` |
| `pkg/ierWorker.py` | `ACTION_IMPORT_CARRIER = 13`, paramètre `carrier`, tâche `_task_import_carrier` |
| `pkg/main_window.py` | `ts_import_carrier()` (refus zip importé, liste de choix du carrier), menu carrier grisé sans carrier, `ts_flam_bt_show()`, `ts_flam_bt_add()`, `worker_launch(..., carrier=)`, `APP_VERSION` |
| `pkg/ui/main.ui`, `pkg/ui/main_ui.py` | « Stories → Import plain.pk (Carrier) », sous-menu « Tools → Flam bt (carrier) » |

Les autres différences avec o-daneel (correctifs d'export, SSL, documentation)
sont décrites dans [`FORK_CHANGES.md`](FORK_CHANGES.md).
