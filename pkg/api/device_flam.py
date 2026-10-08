from glob import glob
import hashlib
import json
import os.path
import shutil
import time
import zipfile
import binascii
import logging
from uuid import UUID

import psutil
import py7zr
import xxtea

from Crypto.Cipher import AES
from PySide6 import QtCore
from PySide6.QtCore import QCoreApplication
                            
from unidecode import unidecode

from pkg.api import stories
from pkg.api.aes_keys import reverse_bytes
from pkg.api.constants import *
from pkg.api.convert_audio import audio_to_mp3, mp3_tag_cleanup, tags_removal_required, transcoding_required
from pkg.api.convert_image import image_to_bitmap_rle4, image_to_liff
from pkg.api.device_lunii import secure_filename
from pkg.api.stories import FILE_META, FILE_STUDIO_JSON, FILE_STUDIO_THUMB, FILE_THUMB, FILE_UUID, StoryList, Story, \
    StudioStory, aes_cipher, aes_decipher, archive_check_7zcontent, archive_check_plain, story_is_flam, story_is_studio, story_is_lunii, archive_check_zipcontent, xxtea_decipher

LIB_BASEDIR = "etc/library/"
LIB_CACHE = "usr/0/library.cache"


class FlamDevice(QtCore.QObject):
    STORIES_BASEDIR = "str/"
    HIDDEN_STORIES_BASEDIR = "str.hidden/"

    signal_story_progress = QtCore.Signal(str, int, int)
    signal_file_progress = QtCore.Signal(str, int, int)
    signal_logger = QtCore.Signal(int, str)
    stories: StoryList

    def __init__(self, mount_point):
        super().__init__()
        self.mount_point = mount_point

        # dummy values
        self.device_version = UNDEF_DEV
        self.UUID = ""
        self.snu = b""
        self.fw_main = "?.?.?"
        self.fw_comm = "?.?.?"
        self.memory_left = 0

        self.story_key = None
        self.story_iv = None
        self.keyfile = b""

        self.debug_plain = False
        self.abort_process = False

        # internal device details
        if not self.__feed_device():
            return

        # loading internal stories + pi update for duplicates filtering
        self.stories = feed_stories(self.mount_point)
        # must run before update_pack_index(), which deletes the firmware library cache
        self.firmware_check_carrier_imports()
        self.update_pack_index()

    @property
    def snu_str(self):
        return self.snu.hex().upper().lstrip("0")

    @property
    def snu_hex(self):
        return self.snu

    def __repr__(self):
        repr_str = f"Flam device on \"{self.mount_point}\"\n"
        repr_str += f"- Main firmware : v{self.fw_main}\n"
        repr_str += f"- Comm firmware : v{self.fw_comm}\n"
        repr_str += f"- SNU      : {binascii.hexlify(self.snu_hex, ' ')}\n"
        repr_str += f"- stories  : {len(self.stories)}x"
        return repr_str

    # opens the .mdf file to read all information related to device
    def __feed_device(self):

        mount_path = Path(self.mount_point)
        mdf_path = mount_path.joinpath(".mdf")

        # checking if specified path is acceptable
        if not os.path.isfile(mdf_path):
            return False

        with open(mdf_path, "rb") as fp_mdf:
            self.__mdf_parse(fp_mdf)
        return True

    def __mdf_parse(self, fp_mdf):
        fp_mdf.seek(2)

        # parsing firmware versions
        raw = fp_mdf.read(48)
        raw_str = raw.decode('utf-8').strip('\x00')
        raw_str = raw_str.replace("main: ", "").replace("comm: ", "")
        versions = raw_str.splitlines()

        self.fw_main = versions[0].split("-")[0]
        if len(versions) > 1:
            self.fw_comm = versions[1].split("-")[0]

        # parsing snu
        snu_str = fp_mdf.read(24).decode('utf-8').rstrip('\x00')
        self.snu = binascii.unhexlify(snu_str)

        # parsing VID/PID
        vid = int.from_bytes(fp_mdf.read(2), 'little')
        pid = int.from_bytes(fp_mdf.read(2), 'little')

        logger = logging.getLogger(LUNII_LOGGER)

        # major v2 use decipher trick
        if self.fw_main.startswith("1."):
            fp_mdf.seek(0x4E)
            self.keyfile = fp_mdf.read(32)
            self.story_key = binascii.hexlify(self.snu) + b"\x00\x00"
            self.story_iv  = b"\x00\x00\x00\x00\x00\x00\x00\x00" + binascii.hexlify(self.snu)[:8]
        else:
            fp_mdf.seek(0x4E)
            self.keyfile = binascii.hexlify(self.snu) + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + binascii.hexlify(self.snu)[:8]
            self.story_key = fp_mdf.read(16)
            self.story_iv = fp_mdf.read(16)

        # checking if md backup file is available 
        FLAM_MD = os.path.join(CFG_DIR, f"{self.snu_str}.v{self.fw_main}.mdf")
        if not os.path.isfile(FLAM_MD):
            logger.log(logging.INFO, f"No backup of v{self.fw_main} metadata file found, creating one...")
            # creating backup of md file
            with open(FLAM_MD, "wb") as fp_mdf_bak:
                fp_mdf.seek(0)
                fp_mdf_bak.write(fp_mdf.read())

        if (vid, pid) == FLAM_USB_VID_PID:
            self.device_version = FLAM_V1
        else:
            self.device_version = UNDEF_DEV

        logger.log(logging.DEBUG, f"\n"
                                       f"SNU : {self.snu_str}\n"
                                       f"HW  : v{self.device_version-(FLAM_V1-1)}\n"
                                       f"FW (main) : {self.fw_main}\n"
                                       f"FW (comm) : {self.fw_comm}\n"
                                       f"VID/PID : 0x{vid:04X} / 0x{pid:04X}")

    def update_pack_index(self):
        self._carriers_cache = None
        lib_path = Path(self.mount_point).joinpath(LIB_BASEDIR)

        # deleting previous files
        list_path = lib_path.joinpath("list")
        list_hidden_path = lib_path.joinpath("list.hidden")
        list_path.unlink(missing_ok=True)
        list_hidden_path.unlink(missing_ok=True)
        # cleaning library cache
        lib_cache = Path(self.mount_point).joinpath(LIB_CACHE)
        lib_cache.unlink(missing_ok=True)
        
        # creating target dir
        lib_path.mkdir(parents=True, exist_ok=True)

        # writing file
        with open(list_path, "w", newline='\n') as fp, open(list_hidden_path, "w", newline='\n') as fp_hidden:
            for story in self.stories:
                if story.hidden:
                    fp_hidden.write(str(story.uuid) + "\n")
                else:
                    fp.write(str(story.uuid) + "\n")
        return

    def __valid_story(self, story_dir):
        return True

    # try to recover lost stories from ./str and ./str.hidden directory
    def recover_stories(self, dry_run: bool):
        recovered = 0

        stories_uuid_found = []
        # getting all stories
        content_dir = os.path.join(self.mount_point, self.STORIES_BASEDIR)
        try:
            contents = [entry for entry in os.listdir(content_dir) if os.path.isdir(os.path.join(content_dir, entry))]
            stories_uuid_found.extend(contents)
            stories_active = [os.path.join(content_dir, entry) for entry in contents]
        except FileNotFoundError:
            return recovered
        # getting all hidden stories
        hidden_content_dir = os.path.join(self.mount_point, self.HIDDEN_STORIES_BASEDIR)
        try:
            stories_uuid_found.extend([entry for entry in os.listdir(hidden_content_dir) if os.path.isdir(os.path.join(hidden_content_dir, entry))])
        except FileNotFoundError:
            return recovered
        stories_uuid_found.sort()

        for index, story in enumerate(stories_uuid_found):
            # directory is a partial UUID
            self.signal_story_progress.emit(story, index, len(stories_uuid_found))

            str_uuid = None
            # looking complete UUID in official DB
            if not str_uuid:
                str_uuid = next((uuid for uuid in stories.DB_OFFICIAL if story.upper() in uuid.upper()), None)
            # looking complete UUID in third party DB
            if not str_uuid:
                str_uuid = next((uuid for uuid in stories.DB_THIRD_PARTY if story.upper() in uuid.upper()), None)
            if not str_uuid:
                str_uuid = story

            # prepare for story analysis
            try:
                full_uuid = UUID(str_uuid)
            except (TypeError, ValueError) as e:
                self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate("FlamDevice", "Not a valid UUID - {}").format(str_uuid))
                continue

            hidden = os.path.join(self.mount_point, self.STORIES_BASEDIR, story) not in stories_active
            if hidden:
                story_dir = os.path.join(hidden_content_dir, story)
            else:
                story_dir = os.path.join(content_dir, story)
            one_story = Story(full_uuid, hidden=hidden)

            if str_uuid not in self.stories:
                # Lost Story
                if self.__valid_story(story_dir):

                    # is it a dry run ?
                    if not dry_run:
                        self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Recovered - {} - {}").format(str(full_uuid).upper(), one_story.name))
                        self.stories.append(one_story)
                    else:
                        self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Found - {} - {}").format(str(full_uuid).upper(), one_story.name))
                    recovered += 1
                else:
                    self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Skipping lost story (seems broken/incomplete) - {} - {}").format(str(full_uuid).upper(), one_story.name))
            else:
                # In DB story
                if not self.__valid_story(story_dir):
                    self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "Already in list but invalid - {} - {}").format(str(full_uuid).upper(), one_story.name))
                else:
                    self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate("FlamDevice", "Already in list - {} - {}").format(str(full_uuid).upper(), one_story.name))

        return recovered

    def cleanup_stories(self):
        removed = 0
        recovered_size = 0

        stories_uuid_found = []
        # getting all stories
        content_dir = os.path.join(self.mount_point, self.STORIES_BASEDIR)
        contents = [entry for entry in os.listdir(content_dir) if os.path.isdir(os.path.join(content_dir, entry))]
        stories_uuid_found.extend(contents)
        stories_active = [os.path.join(content_dir, entry) for entry in contents]

        # getting all hidden stories
        hidden_content_dir = os.path.join(self.mount_point, self.HIDDEN_STORIES_BASEDIR)
        stories_uuid_found.extend([entry for entry in os.listdir(hidden_content_dir) if os.path.isdir(os.path.join(hidden_content_dir, entry))])
        
        stories_uuid_found.sort()

        for index, story in enumerate(stories_uuid_found):
            # directory is a partial UUID
            self.signal_story_progress.emit(story, index, len(stories_uuid_found))

            if story not in self.stories:
                # remove it
                try:
                    hidden = os.path.join(self.mount_point, self.STORIES_BASEDIR, story) not in stories_active
                    if hidden:
                        lost_story_path = os.path.join(hidden_content_dir, story)
                    else:
                        lost_story_path = os.path.join(content_dir, story)

                    # computing lost size
                    for parent_dir, _, files in os.walk(lost_story_path):
                        for file in files:
                            recovered_size += os.path.getsize(os.path.join(parent_dir, file))

                    # removing whole directory
                    self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Deleting - {}").format(lost_story_path))
                    shutil.rmtree(lost_story_path)
                    removed += 1
                except (OSError, PermissionError) as e:
                    self.signal_logger.emit(logging.WARN, QCoreApplication.translate("FlamDevice", "Failed to delete - {}").format(lost_story_path))
                    self.signal_logger.emit(logging.ERROR, e)

        return removed, recovered_size//1024//1024

    def cipher(self, buffer, key, iv=None, offset=0, enc_len=512):
        if self.debug_plain:
            return buffer

        return aes_cipher(buffer, key, iv, offset, enc_len)

    def __get_ciphered_data(self, file, data, flam_story, force=False):
        if not flam_story:
            # LUNII
            key = reverse_bytes(self.story_key)
            iv = reverse_bytes(self.story_iv)

            if file.endswith("ni") or file.endswith("nm"):
                key = None
        else:
            # FLAM
            key = None
            if file.endswith(".lua") or file.endswith(".plain") or force:
                key = self.story_key
                iv = self.story_iv

        # data len to cipher
        cipher_len = len(data) if flam_story else 0x200

        # process file with correct key
        if key:
            return self.cipher(data, key, iv, enc_len=cipher_len)

        return data

    def  __get_flam_ciphered_name(self, file: str):
        file = file.removesuffix('.plain')
        
        if file.endswith(".lua"):
            file = file.replace(".lua", ".lsf")

        return file

    def __get_lunii_ciphered_name(self, file: str, studio_ri=False, studio_si=False):
        file = file.removesuffix('.plain')

        if studio_ri:
            file = f"rf/000/{file}"
        if studio_si:
            file = f"sf/000/{file}"

        file = file.lower().removesuffix('.mp3')
        file = file.lower().removesuffix('.bmp')

        # upcasing filename
        bn = os.path.basename(file)
        if len(bn) >= 8:
            file = os.path.join(os.path.dirname(file), bn.upper())

        # upcasing uuid dir if present
        # dn = os.path.dirname(file)
        # if len(dn) >= 8:
        #     dir_head = file[0:8]
        #     if "/" not in dir_head and "\\" not in dir_head:
        #         file = dir_head.upper() + file[8:]
        # file = file.replace("\\", "/")

        # self.signal_logger.emit(logging.DEBUG, f"Target file : {file}")
        return file

    def import_story(self, story_path):
        archive_type = TYPE_UNK

        self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "🚧 Loading {}...").format(story_path))

        archive_size = os.path.getsize(story_path)
        free_space = psutil.disk_usage(str(self.mount_point)).free
        if archive_size >= free_space:
            self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "Not enough space left on Flam (only {}MB)").format(free_space//1024//1024))
            return False

        # identifying based on filename
        if story_path.lower().endswith(EXT_PK_PLAIN):
            archive_type = archive_check_plain(story_path)
        elif story_path.lower().endswith(EXT_ZIP):
            archive_type = archive_check_zipcontent(story_path)
        elif story_path.lower().endswith(EXT_7Z):
            archive_type = archive_check_7zcontent(story_path)
        elif story_path.lower().endswith(EXT_PK_VX):
            archive_type = archive_check_zipcontent(story_path)

        # is flam firmware enough to support Lunii stories ?
        if self.fw_main.startswith("1.") and archive_type in [TYPE_LUNII_PLAIN, TYPE_LUNII_V2_ZIP, TYPE_LUNII_V2_7Z, TYPE_STUDIO_ZIP, TYPE_STUDIO_7Z]:
            self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "Please update your Flam with v2.x.x to support Lunii Stories"))
            return None

        # processing story
        if archive_type == TYPE_LUNII_PLAIN:
            self.signal_logger.emit(logging.DEBUG, "Archive => TYPE_LUNII_PLAIN")
            return self.import_lunii_plain(story_path)
        elif archive_type == TYPE_FLAM_PLAIN:
            self.signal_logger.emit(logging.DEBUG, "Archive => TYPE_FLAM_PLAIN")
            return self.import_flam_plain(story_path)
        elif archive_type == TYPE_FLAM_ZIP:
            self.signal_logger.emit(logging.DEBUG, "Archive => TYPE_FLAM_ZIP")
            return self.import_flam_zip(story_path)
        elif archive_type == TYPE_FLAM_7Z:
            self.signal_logger.emit(logging.DEBUG, "Archive => TYPE_FLAM_7Z")
            return self.import_flam_7z(story_path)
        elif archive_type == TYPE_LUNII_V2_ZIP:
            self.signal_logger.emit(logging.DEBUG, "Archive => TYPE_LUNII_V2_ZIP")
            return self.import_lunii_v2_zip(story_path)
        elif archive_type == TYPE_LUNII_FLAM_ZIP:
            self.signal_logger.emit(logging.DEBUG, "Archive => TYPE_LUNII_FLAM_ZIP")
            return self.import_lunii_flam_zip(story_path)
        elif archive_type == TYPE_LUNII_V2_7Z:
            self.signal_logger.emit(logging.DEBUG, "Archive => TYPE_LUNII_V2_7Z")
            return self.import_lunii_v2_7z(story_path)
        elif archive_type == TYPE_STUDIO_ZIP:
            self.signal_logger.emit(logging.DEBUG, "Archive => TYPE_STUDIO_ZIP")
            return self.import_studio_zip(story_path)
        elif archive_type == TYPE_STUDIO_7Z:
            self.signal_logger.emit(logging.DEBUG, "Archive => TYPE_STUDIO_7Z")
            return self.import_studio_7z(story_path)
        else:
            self.signal_logger.emit(logging.ERROR, "Archive => Unsupported type 0x{:02X}".format(archive_type))

        return None
    
    def import_lunii_plain(self, story_path):
        # checking if archive is OK
        try:
            with zipfile.ZipFile(file=story_path):
                pass  # If opening succeeds, the archive is valid
        except zipfile.BadZipFile as e:
            self.signal_logger.emit(logging.ERROR, e)
            return False

        
        # opening zip file
        with zipfile.ZipFile(file=story_path) as zip_file:
            # reading all available files
            zip_contents = zip_file.namelist()
            if FILE_UUID not in zip_contents:
                self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "No UUID file found in archive. Unable to add this story."))
                return False

            # getting UUID file
            try:
                new_uuid = UUID(bytes=zip_file.read(FILE_UUID))
            except ValueError as e:
                self.signal_logger.emit(logging.ERROR, e)
                return False

            # checking if UUID already loaded
            if str(new_uuid) in self.stories:
                self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "'{}' is already loaded !").format(self.stories.get_story(new_uuid).name))
                return False

            # thirdparty story ?
            if FILE_META in zip_contents:
                # creating story entry in thirdparty db
                meta = zip_file.read(FILE_META)
                s_meta = json.loads(meta)
                if s_meta.get("uuid").upper() != str(new_uuid).upper():
                    return False
                stories.thirdparty_db_add_story(new_uuid, s_meta.get("title"), s_meta.get("description"))
            if FILE_THUMB in zip_contents:
                # creating story picture in cache
                image_data = zip_file.read(FILE_THUMB)
                stories.thirdparty_db_add_thumb(new_uuid, image_data)

            # decompressing story contents
            long_uuid = str(new_uuid).lower()
            short_uuid = long_uuid[28:]
            output_path = Path(self.mount_point).joinpath(f"{self.STORIES_BASEDIR}{long_uuid}")
            if not output_path.exists():
                output_path.mkdir(parents=True)

            # Loop over each file
            for index, file in enumerate(zip_contents):
                self.signal_story_progress.emit(short_uuid, index, len(zip_contents))
                # abort requested ? early exit
                if self.abort_process:
                    self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "Import aborted, performing cleanup on current story..."))
                    self.__clean_up_story_dir(new_uuid)
                    return False

                # skipping .plain.pk specific files 
                if file in [FILE_UUID, FILE_META, FILE_THUMB]:
                    continue
                if file.endswith("bt"):
                    continue

                # checking zip content
                info = zip_file.getinfo(file)
                if info.is_dir():
                    continue

                # Extract each zip file
                data_plain = zip_file.read(file)

                # updating filename, and ciphering header if necessary
                data = self.__get_ciphered_data(file, data_plain, False)
                file_newname = self.__get_lunii_ciphered_name(file)

                target: Path = output_path.joinpath(file_newname)

                # create target directory
                if not target.parent.exists():
                    target.parent.mkdir(parents=True)
                # write target file
                self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate("FlamDevice", "File {}/{} > {}").format(index+1, len(zip_contents), file_newname))
                self.__write_with_progress(target, data)

        # keyfile creation
        self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Authorization file creation..."))
        bt_path = output_path.joinpath("key")
        with open(bt_path, "wb") as fp_bt:
            fp_bt.write(self.keyfile)

        # story creation
        loaded_story = Story(new_uuid)

        # creating info file creation
        self.__write_info(loaded_story, output_path)

        # creating thumbnail image
        self.__write_thumbnail(loaded_story, output_path)

        # updating .pi file to add new UUID
        self.stories.append(loaded_story)
        self.update_pack_index()

        return True

    @staticmethod
    def _read_carrier_from_zip(zip_path: str) -> dict | None:
        """Extrait bt + key-file depuis un .zip Flam contenant un fichier 'bt'.

        Format attendu (zip officiel Lunii ou backup avec bt) :
          str/<UUID>/bt    <- 32 o : story_key(16) | story_iv(16)
          str/<UUID>/key   <- 32 o : key-file (optionnel, peut être lu sur device)

        Retourne { "uuid_str": str, "bt": bytes(32), "key_file": bytes|None }
        ou None si bt absent.
        """
        try:
            with zipfile.ZipFile(zip_path) as z:
                names = z.namelist()
                bt_entries  = [e for e in names if os.path.basename(e) == "bt"]
                key_entries = [e for e in names if os.path.basename(e) == "key"]
                if not bt_entries:
                    return None
                bt = z.read(bt_entries[0])
                if len(bt) < 32:
                    return None
                uuid_str = Path(bt_entries[0]).parent.name
                key_file = z.read(key_entries[0]) if key_entries else None
                return {"uuid_str": uuid_str, "bt": bt[:32], "key_file": key_file}
        except Exception:
            return None

    @staticmethod
    def _load_known_bts() -> list:
        """Lit les bt connus depuis FLAM_KNOWN_BTS (~/.lunii-qt/flam_known_bts.txt).

        Fichier volontairement hors dépôt : ces clés appartiennent à des comptes
        Lunii précis. Format : une ligne par bt, 64 caractères hexadécimaux
        (story_key 16 o + story_iv 16 o), espaces ignorés, '#' = commentaire.
        Fichier absent ou ligne invalide : ignoré silencieusement.
        """
        bts = []
        if not os.path.isfile(FLAM_KNOWN_BTS):
            return bts
        with open(FLAM_KNOWN_BTS, "r", encoding="utf-8") as fp:
            for line in fp:
                hex_str = line.split("#", 1)[0].replace(" ", "").strip()
                if len(hex_str) != 64:
                    continue
                try:
                    bts.append(bytes.fromhex(hex_str))
                except ValueError:
                    continue
        return bts

    @staticmethod
    def save_known_bt(bt: bytes, comment: str) -> bool:
        """Ajoute un bt à FLAM_KNOWN_BTS s'il n'y est pas déjà.

        Le fichier est créé (avec un en-tête explicatif) s'il n'existe pas.
        Retourne True si le bt a été ajouté, False s'il était déjà connu.
        """
        if len(bt) != 32 or bt in FlamDevice._load_known_bts():
            return False
        new_file = not os.path.isfile(FLAM_KNOWN_BTS)
        os.makedirs(os.path.dirname(FLAM_KNOWN_BTS), exist_ok=True)
        with open(FLAM_KNOWN_BTS, "a", encoding="utf-8") as fp:
            if new_file:
                fp.write("# Lunii.QT - bt Flam connus (story_key 16 o + story_iv 16 o, hex)\n"
                         "# Une ligne par bt, '#' = commentaire. Fichier personnel : ne pas publier.\n")
            fp.write(f"\n# {comment} - ajouté le {time.strftime('%Y-%m-%d')}\n")
            fp.write(f"{bt[:16].hex()} {bt[16:32].hex()}\n")
        return True

    def stories_matching_bt(self, bt: bytes) -> list:
        """Histoires du device (hors imports lunii-qt) dont l'info se déchiffre avec ce bt."""
        matching = []
        for story in self.stories:
            story_path = os.path.join(
                self.mount_point,
                self.STORIES_BASEDIR if not story.hidden else self.HIDDEN_STORIES_BASEDIR,
                str(story.uuid))
            key_path = os.path.join(story_path, "key")
            info_path = os.path.join(story_path, "info")
            if not (os.path.isfile(key_path) and os.path.isfile(info_path)):
                continue
            with open(key_path, "rb") as fp:
                if fp.read(32) == self.keyfile[:32]:
                    continue
            with open(info_path, "rb") as fp:
                if self._bt_decrypts_info(bt, fp.read(4096)):
                    matching.append(story)
        return matching

    @staticmethod
    def _bt_decrypts_info(bt: bytes, info_data: bytes) -> bool:
        """Vrai si le bt déchiffre le fichier info en texte lisible.

        Déchiffrement AES-CBC de tout le fichier (quelques dizaines d'octets).
        Valide si le résultat, hors padding nul final, est de l'UTF-8 strict
        dont ≥90 % des caractères sont imprimables ou des retours à la ligne.
        L'UTF-8 strict accepte les accents des titres et rejette le bruit
        produit par une mauvaise clé.
        """
        length = len(info_data) // 16 * 16
        if length == 0:
            return False
        try:
            plain = AES.new(bt[:16], AES.MODE_CBC, bt[16:32]).decrypt(info_data[:length])
            text = plain.rstrip(b"\x00").decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return False
        if len(text) < 4:
            return False
        printable = sum(1 for c in text if c.isprintable() or c in "\r\n")
        return printable / len(text) >= 0.90

    def _detect_bt_from_info(self, info_data: bytes) -> bytes | None:
        """Tente de retrouver le bt en déchiffrant info avec les bt connus.

        Candidats, dans l'ordre :
          1. bt du fichier FLAM_KNOWN_BTS (~/.lunii-qt/flam_known_bts.txt)
          2. bt déjà détectés sur ce device (cache mémoire)

        La clé dérivée du SNU n'est volontairement PAS candidate : elle ne
        déchiffre que les histoires importées par lunii-qt, dont le key-file
        est illisible par le firmware récent (mauvais carriers).
        """
        if not hasattr(self, "_detected_bts"):
            self._detected_bts = []

        candidates = self._load_known_bts()
        for cached in self._detected_bts:
            if cached not in candidates:
                candidates.append(cached)

        for bt_candidate in candidates:
            if self._bt_decrypts_info(bt_candidate, info_data):
                if bt_candidate not in self._detected_bts:
                    self._detected_bts.append(bt_candidate)
                return bt_candidate
        return None

    def _clog(self, level, message):
        # diagnostic logs for carrier feature, prefixed to be easy to grep / share
        self.signal_logger.emit(level, f"[carrier] {message}")

    @staticmethod
    def _bt_fingerprint(bt: bytes) -> str:
        # short, non reversible id of a bt : allows comparing logs without leaking the key
        return hashlib.sha256(bt).hexdigest()[:8]

    def _info_title(self, bt: bytes, info_data: bytes) -> str:
        length = len(info_data) // 16 * 16
        if not length:
            return ""
        try:
            plain = AES.new(bt[:16], AES.MODE_CBC, bt[16:32]).decrypt(info_data[:length])
            return plain.rstrip(b"\x00").decode("utf-8", "replace").splitlines()[0][:60]
        except (ValueError, IndexError):
            return ""

    @staticmethod
    def _load_carrier_imports() -> dict:
        try:
            with open(FLAM_CARRIER_IMPORTS, "r", encoding="utf-8") as fp:
                return json.load(fp)
        except (OSError, ValueError):
            return {}

    @staticmethod
    def _save_carrier_imports(records: dict):
        os.makedirs(os.path.dirname(FLAM_CARRIER_IMPORTS), exist_ok=True)
        with open(FLAM_CARRIER_IMPORTS, "w", encoding="utf-8") as fp:
            json.dump(records, fp, indent=2, ensure_ascii=False)

    def _record_carrier_import(self, story_uuid: str, title: str, carrier: dict):
        """Mémorise un import carrier pour le contrôle firmware au prochain branchement."""
        records = self._load_carrier_imports()
        records.setdefault(self.snu_str, {})[story_uuid] = {
            "title":     title,
            "imported":  time.strftime("%Y-%m-%d %H:%M:%S"),
            "fw_main":   self.fw_main,
            "carrier":   f"{carrier['key_file'][:4].hex()}.../{self._bt_fingerprint(carrier['bt'])}",
            "status":    "pending",
            "checked":   None,
        }
        self._save_carrier_imports(records)

    def firmware_check_carrier_imports(self) -> dict:
        """Vérifie, via usr/0/library.cache, que le firmware a déchiffré les histoires importées en carrier.

        Le firmware reconstruit library.cache au démarrage avec les titres qu'il a su déchiffrer ;
        lunii-qt le supprime à chaque écriture (update_pack_index). Donc :
          - cache absent              -> "pending" (la Flam n'a pas redémarré depuis la dernière écriture)
          - cache présent + titre     -> "ok"      (titre déchiffré par le firmware)
          - cache présent, sans titre -> "fail"    (cache reconstruit après l'import, titre absent)
        À appeler AVANT update_pack_index(). Retourne { uuid: status } pour cette Flam.
        """
        logger = logging.getLogger(LUNII_LOGGER)
        records = self._load_carrier_imports()
        device_records = records.get(self.snu_str, {})
        present = {str(s.uuid) for s in self.stories}
        to_check = {u: r for u, r in device_records.items() if u in present}
        if not to_check:
            return {}

        cache_path = Path(self.mount_point).joinpath(LIB_CACHE)
        cache = cache_path.read_bytes() if cache_path.is_file() else None
        results = {}
        for story_uuid, rec in to_check.items():
            # le titre d'info peut contenir de longs blancs : on cherche son premier segment
            needle = rec["title"].split("  ")[0].strip()[:32]
            if cache is None:
                status = "pending"
                detail = "library.cache absent : ejecter la Flam, la redemarrer, puis la rebrancher"
            elif needle and needle.encode("utf-8") in cache:
                status = "ok"
                detail = "titre dechiffre par le firmware"
            else:
                status = "fail"
                detail = "titre absent du cache reconstruit : histoire probablement illisible par le firmware"
            if status != "pending":
                rec["status"], rec["checked"] = status, time.strftime("%Y-%m-%d %H:%M:%S")
            results[story_uuid] = status
            logger.log(logging.WARNING if status == "fail" else logging.INFO,
                       f"[carrier] firmware check {story_uuid[-8:].upper()} {rec['title'][:40]!r} : "
                       f"{status.upper()} - {detail} (fw {self.fw_main}, carrier {rec['carrier']}, "
                       f"cache {len(cache) if cache is not None else 0}B)")
        self._save_carrier_imports(records)
        return results

    def find_available_carriers(self, refresh: bool = False) -> list:
        """Retourne les histoires du device utilisables comme carrier, triées.

        Exclusion : une histoire dont le key-file == self.keyfile a été importée
        par lunii-qt ; ce key-file n'est pas lisible par le firmware récent,
        elle ne peut donc pas servir de carrier.

        Sources du bt, par ordre de fiabilité :
          "bt"      : fichier bt direct dans str/<UUID>/bt
          "sibling" : bt partagé avec une histoire sœur du même compte
          "info"    : détection par déchiffrement du fichier info

        "verified" = le bt déchiffre bien le fichier info de l'histoire.
        Tri : vérifiés d'abord, puis par source.

        Retourne une liste de dicts :
          { "story": Story, "key_file": bytes(32), "bt": bytes(32),
            "source": str, "verified": bool }
        """
        # résultat mis en cache, invalidé par update_pack_index()
        if not refresh and getattr(self, "_carriers_cache", None) is not None:
            return self._carriers_cache

        known_bts = self._load_known_bts()
        self._clog(logging.INFO, f"scan start : Flam SNU {self.snu_str}, fw main {self.fw_main}, "
                                 f"fw comm {self.fw_comm}, {len(self.stories)} stories, "
                                 f"device keyfile {self.keyfile[:4].hex()}...")
        self._clog(logging.INFO, f"known bt file : {FLAM_KNOWN_BTS} "
                                 f"({'present' if os.path.isfile(FLAM_KNOWN_BTS) else 'absent'}, "
                                 f"{len(known_bts)} bt : {', '.join(self._bt_fingerprint(b) for b in known_bts) or '-'})")

        source_rank = {"bt": 0, "sibling": 1, "info": 2}
        carriers = []
        stats = {"no_key": 0, "luniiqt": 0, "no_bt": 0}
        for story in self.stories:
            story_path = os.path.join(
                self.mount_point,
                self.STORIES_BASEDIR if not story.hidden else self.HIDDEN_STORIES_BASEDIR,
                str(story.uuid))
            tag = f"{story.short_uuid} {story.name[:40]!r}"

            key_path = os.path.join(story_path, "key")
            if not os.path.isfile(key_path):
                stats["no_key"] += 1
                self._clog(logging.INFO, f"{tag} : skipped, no key file")
                continue
            with open(key_path, "rb") as fp:
                key_data = fp.read(32)

            # histoire importée par lunii-qt : key-file non lisible par le firmware
            if key_data == self.keyfile[:32]:
                stats["luniiqt"] += 1
                self._clog(logging.INFO, f"{tag} : skipped, key = device keyfile (lunii-qt re-ciphered import)")
                continue

            info_data = b""
            info_path = os.path.join(story_path, "info")
            if os.path.isfile(info_path):
                with open(info_path, "rb") as fp:
                    info_data = fp.read(4096)

            bt_data = None
            source = None

            # Source 1 : bt direct dans le dossier
            bt_path = os.path.join(story_path, "bt")
            if os.path.isfile(bt_path):
                with open(bt_path, "rb") as fp:
                    candidate = fp.read(32)
                if len(candidate) == 32:
                    bt_data, source = candidate, "bt"
                else:
                    self._clog(logging.WARNING, f"{tag} : bt file has wrong size ({len(candidate)} bytes)")

            # Source 2 : bt partagé avec une histoire sœur (même compte)
            if not bt_data:
                candidate = self.__find_shared_bt(key_data, story.uuid)
                if candidate:
                    bt_data, source = candidate, "sibling"

            # Source 3 : détection par déchiffrement du fichier info
            if not bt_data and info_data:
                candidate = self._detect_bt_from_info(info_data)
                if candidate:
                    bt_data, source = candidate, "info"

            if bt_data and len(bt_data) == 32:
                verified = source == "info" or self._bt_decrypts_info(bt_data, info_data)
                carriers.append({
                    "story":    story,
                    "key_file": key_data,
                    "bt":       bt_data,
                    "source":   source,
                    "verified": verified,
                })
                self._clog(logging.INFO, f"{tag} : CARRIER key {key_data[:4].hex()}... bt {self._bt_fingerprint(bt_data)} "
                                         f"source={source} verified={verified} info={len(info_data)}B"
                                         + (f" title={self._info_title(bt_data, info_data)!r}" if verified else ""))
            else:
                stats["no_bt"] += 1
                self._clog(logging.INFO, f"{tag} : no bt found (key {key_data[:4].hex()}..., "
                                         f"bt file {'yes' if os.path.isfile(bt_path) else 'no'}, info {len(info_data)}B)")

        carriers.sort(key=lambda c: (not c["verified"], source_rank[c["source"]]))

        # sauvegarde des bt lus en fichier : Lunii peut les faire disparaître
        for c in carriers:
            if c["source"] in ("bt", "sibling") and c["verified"]:
                if self.save_known_bt(c["bt"], f"key {c['key_file'][:4].hex()}... trouvé sur Flam {self.snu_str} "
                                               f"({c['story'].name}, fichier bt)"):
                    self._clog(logging.INFO, f"new bt {self._bt_fingerprint(c['bt'])} saved to {FLAM_KNOWN_BTS}")

        accounts = {c["key_file"][:4].hex() for c in carriers}
        self._clog(logging.INFO, f"scan end : {len(carriers)} carriers ({len(accounts)} account(s) : "
                                 f"{', '.join(sorted(accounts)) or '-'}), skipped : {stats['luniiqt']} lunii-qt imports, "
                                 f"{stats['no_bt']} without bt, {stats['no_key']} without key")

        self._carriers_cache = carriers
        return carriers

    def import_flam_plain_carrier(self, plain_pk_path: str, carrier: dict) -> bool:
        """Import un .plain.pk Flam en réutilisant le bt + key-file d'un carrier.

        carrier = { "key_file": bytes(32), "bt": bytes(32) }
        Peut venir de find_available_carriers() ou _read_carrier_from_zip().

        Contourne V-9 (device_iv inconnu fw 1.x) : re-chiffre le contenu avec
        bt_carrier, injecte le key-file carrier -> firmware déchiffre correctement.
        """
        ts_start = time.time()
        carrier_sk  = carrier["bt"][:16]
        carrier_iv  = carrier["bt"][16:32]
        carrier_key = carrier["key_file"]

        carrier_story = carrier.get("story")
        self._clog(logging.INFO, f"import start : {plain_pk_path} ({os.path.getsize(plain_pk_path) // 1024} KB)")
        self._clog(logging.INFO, f"device : Flam SNU {self.snu_str}, fw main {self.fw_main}, fw comm {self.fw_comm}")
        self._clog(logging.INFO, f"carrier : {carrier_story.short_uuid + ' ' + repr(carrier_story.name) if carrier_story else 'zip ' + str(carrier.get('uuid_str'))} "
                                 f"key {carrier_key[:4].hex() if carrier_key else '-'}... "
                                 f"bt {self._bt_fingerprint(carrier['bt'])} source={carrier.get('source', 'zip')} "
                                 f"verified={carrier.get('verified', '?')}")

        if len(carrier_sk) != 16 or not carrier_key or len(carrier_key) < 32:
            self.signal_logger.emit(logging.ERROR, QCoreApplication.translate(
                "FlamDevice", "Carrier data invalid (bt or key_file wrong size)"))
            return False

        # --- Valider le plain.pk ---
        try:
            with zipfile.ZipFile(file=plain_pk_path):
                pass
        except zipfile.BadZipFile as e:
            self.signal_logger.emit(logging.ERROR, e)
            return False

        with zipfile.ZipFile(file=plain_pk_path) as z:
            zip_contents = z.namelist()
            if FILE_UUID not in zip_contents:
                self.signal_logger.emit(logging.ERROR, QCoreApplication.translate(
                    "FlamDevice", "No UUID file found in archive. Unable to add this story."))
                return False

            try:
                new_uuid = UUID(bytes=z.read(FILE_UUID))
            except ValueError as e:
                self.signal_logger.emit(logging.ERROR, e)
                return False

            if str(new_uuid) in self.stories:
                self.signal_logger.emit(logging.WARNING, QCoreApplication.translate(
                    "FlamDevice", "'{}' is already loaded !").format(
                    self.stories.get_story(new_uuid).name))
                return False

            version = z.read("version").decode("utf-8", "replace").strip() if "version" in zip_contents else "-"
            nb_lua = sum(1 for f in zip_contents if f.endswith(".lua"))
            self._clog(logging.INFO, f"plain.pk : uuid {new_uuid}, {len(zip_contents)} entries, {nb_lua} lua, "
                                     f"version file {version!r}, info.plain {'yes' if 'info.plain' in zip_contents else 'NO'}, "
                                     f"main.lua {'yes' if 'main.lua' in zip_contents else 'NO'}")

            long_uuid  = str(new_uuid).lower()
            short_uuid = long_uuid[28:]
            output_path = Path(self.mount_point) / self.STORIES_BASEDIR / long_uuid
            if not output_path.exists():
                output_path.mkdir(parents=True)

            # --- Re-chiffrer avec le bt carrier ---
            nb_ciphered = nb_verbatim = size_written = 0
            for index, file in enumerate(zip_contents):
                self.signal_story_progress.emit(short_uuid, index, len(zip_contents))

                if self.abort_process:
                    self.signal_logger.emit(logging.WARNING, QCoreApplication.translate(
                        "FlamDevice", "Import aborted, performing cleanup on current story..."))
                    self.__clean_up_story_dir(new_uuid)
                    return False

                if file in [FILE_UUID, FILE_META, FILE_THUMB]:
                    continue
                if z.getinfo(file).is_dir():
                    continue

                data_plain = z.read(file)

                # Chiffrement AES-CBC bt carrier sur lua + info.plain
                if file.endswith(".lua") or file.endswith(".plain"):
                    data = aes_cipher(data_plain, carrier_sk, carrier_iv, 0, len(data_plain))
                    nb_ciphered += 1
                else:
                    data = data_plain   # mp3, lif, version, mp3map -> verbatim
                    nb_verbatim += 1

                out_name = self.__get_flam_ciphered_name(file)
                target = output_path / out_name
                if not target.parent.exists():
                    target.parent.mkdir(parents=True)

                self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate(
                    "FlamDevice", "File {}/{} > {}").format(
                    index + 1, len(zip_contents), out_name))
                self.__write_with_progress(target, data)
                size_written += len(data)

        self._clog(logging.INFO, f"files written : {nb_ciphered} ciphered (lua/info), {nb_verbatim} verbatim, "
                                 f"{size_written // 1024} KB")

        # --- Injecter le key-file carrier ---
        self.signal_logger.emit(logging.INFO, QCoreApplication.translate(
            "FlamDevice", "Authorization file creation (carrier)..."))
        (output_path / "key").write_bytes(carrier_key[:32])

        # --- Relecture : le contenu écrit se déchiffre-t-il avec le bt carrier ? ---
        info_path = output_path / "info"
        info_data = info_path.read_bytes() if info_path.exists() else b""
        readback_ok = self._bt_decrypts_info(carrier["bt"], info_data)
        self._clog(logging.INFO if readback_ok else logging.ERROR,
                   f"readback : key {(output_path / 'key').read_bytes()[:4].hex()}..., info {len(info_data)}B, "
                   f"decrypts={readback_ok}, title={self._info_title(carrier['bt'], info_data)!r}")

        # --- Mémoriser l'import pour le contrôle firmware au prochain branchement ---
        if readback_ok:
            self._record_carrier_import(str(new_uuid), self._info_title(carrier["bt"], info_data), carrier)

        # --- Enregistrer l'histoire ---
        loaded_story = Story(new_uuid)
        self.stories.append(loaded_story)
        self.update_pack_index()
        self._clog(logging.INFO, f"import end : {short_uuid} in {time.time() - ts_start:.0f} s. "
                                 f"To validate : eject the Flam, reboot it, check the title is readable and the story plays, "
                                 f"then plug it back : Lunii.QT logs a '[carrier] firmware check' line. "
                                 f"Report the result with these [carrier] logs.")
        self.signal_logger.emit(logging.INFO, QCoreApplication.translate(
            "FlamDevice", "✅ Carrier import OK — {}").format(short_uuid))
        return True

    def import_flam_plain(self, story_path):
        # checking if archive is OK
        try:
            with zipfile.ZipFile(file=story_path):
                pass  # If opening succeeds, the archive is valid
        except zipfile.BadZipFile as e:
            self.signal_logger.emit(logging.ERROR, e)
            return False

        # opening zip file
        with zipfile.ZipFile(file=story_path) as zip_file:
            # reading all available files
            zip_contents = zip_file.namelist()
            if FILE_UUID not in zip_contents:
                self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "No UUID file found in archive. Unable to add this story."))
                return False

            # getting UUID file
            try:
                new_uuid = UUID(bytes=zip_file.read(FILE_UUID))
            except ValueError as e:
                self.signal_logger.emit(logging.ERROR, e)
                return False

            # checking if UUID already loaded
            if str(new_uuid) in self.stories:
                self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "'{}' is already loaded !").format(self.stories.get_story(new_uuid).name))
                return False

            # decompressing story contents
            long_uuid = str(new_uuid).lower()
            short_uuid = long_uuid[28:]
            output_path = Path(self.mount_point).joinpath(f"{self.STORIES_BASEDIR}{long_uuid}")
            if not output_path.exists():
                output_path.mkdir(parents=True)

            # Loop over each file
            for index, file in enumerate(zip_contents):
                self.signal_story_progress.emit(short_uuid, index, len(zip_contents))
                # abort requested ? early exit
                if self.abort_process:
                    self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "Import aborted, performing cleanup on current story..."))
                    self.__clean_up_story_dir(new_uuid)
                    return False

                # skipping .plain.pk specific files 
                if file in [FILE_UUID, FILE_META, FILE_THUMB]:
                    continue

                # checking zip content
                info = zip_file.getinfo(file)
                if info.is_dir():
                    continue

                # Extract each zip file
                data_plain = zip_file.read(file)

                # updating filename, and ciphering header if necessary
                data = self.__get_ciphered_data(file, data_plain, True)
                file_newname = self.__get_flam_ciphered_name(file)

                target: Path = output_path.joinpath(file_newname)

                # create target directory
                if not target.parent.exists():
                    target.parent.mkdir(parents=True)
                # write target file
                self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate("FlamDevice", "File {}/{} > {}").format(index+1, len(zip_contents), file_newname))
                self.__write_with_progress(target, data)

        # keyfile creation
        self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Authorization file creation..."))
        key_path = output_path.joinpath("key")
        with open(key_path, "wb") as fp_key:
            fp_key.write(self.keyfile)

        # story creation
        loaded_story = Story(new_uuid)

         # updating .pi file to add new UUID
        self.stories.append(loaded_story)
        self.update_pack_index()

        return True
    
    def import_flam_zip(self, story_path):
        # checking if archive is OK
        try:
            with zipfile.ZipFile(file=story_path):
                pass  # If opening succeeds, the archive is valid
        except zipfile.BadZipFile as e:
            self.signal_logger.emit(logging.ERROR, e)
            return False

        # opening zip file
        with zipfile.ZipFile(file=story_path) as zip_file:
            # reading all available files
            zip_contents = zip_file.namelist()

            if story_is_lunii(zip_contents) or story_is_studio(zip_contents):
                self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "Archive seems to be made of Lunii story (Flam story expected)"))
                return False

            # checking for keyfile
            storykeys_file = [entry for entry in zip_contents if entry.endswith("bt")]
            if storykeys_file:
                self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Transciphering Flam story"))
                data = zip_file.read(storykeys_file[0])
                story_key = data[:16]
                story_iv = data[16:]
            else:
                keyfile = [entry for entry in zip_contents if entry.endswith("key")]
                if not keyfile:
                    self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "Flam story backup is incomplete, missing key file."))
                    return False
                self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Restoring Flam story backup"))

            # getting UUID from path
            uuid_path = Path(zip_contents[0])
            uuid_str = uuid_path.parents[0].name if uuid_path.parents[0].name else uuid_path.name

            if len(uuid_str) >= 16:  # long enough to be a UUID
                # self.signal_logger.emit(logging.DEBUG, uuid_str)
                try:
                    if "-" not in uuid_str:
                        new_uuid = UUID(bytes=binascii.unhexlify(uuid_str))
                    else:
                        new_uuid = UUID(uuid_str)
                except ValueError as e:
                    self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "UUID parse error {}").format(e))
                    return False
            else:
                self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "UUID directory is missing in archive !"))
                return False

            # checking if UUID already loaded
            if str(new_uuid) in self.stories:
                self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "'{}' is already loaded, aborting !").format(self.stories.get_story(new_uuid).name))
                return False

            # decompressing story contents
            short_uuid = str(new_uuid).upper()[28:]
            output_path = Path(self.mount_point).joinpath(f"{self.STORIES_BASEDIR}")
            if not output_path.exists():
                output_path.mkdir(parents=True)

            # Loop over each file
            for index, file in enumerate(zip_contents):
                if self.abort_process:
                    self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "Import aborted, performing cleanup on current story..."))
                    self.__clean_up_story_dir(new_uuid)
                    return False

                self.signal_story_progress.emit(short_uuid, index, len(zip_contents))

                if zip_file.getinfo(file).is_dir():
                    continue

                # Extract each zip file
                self.signal_logger.emit(logging.DEBUG, f"File {index+1}/{len(zip_contents)} > {file}")
                data = zip_file.read(file)

                # transcoding if necessary
                if storykeys_file:
                    if file.endswith(".lsf") or file.endswith("info"):
                        self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate("FlamDevice", "Transciphering file {}").format(file))
                        # decipher
                        data_plain = aes_decipher(data, story_key, story_iv, 0, len(data))
                        # cipher
                        data = self.__get_ciphered_data(file, data_plain, True, True)

                target: Path = output_path.joinpath(file)

                # create target directory
                if not target.parent.exists():
                    target.parent.mkdir(parents=True)
                # write target file
                self.__write_with_progress(target, data)

        # keyfile creation due to transciphering
        if storykeys_file:
            self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Authorization file creation..."))
            new_keyfile = os.path.join(output_path, str(new_uuid), "key")
            with open(new_keyfile, "wb") as fp_key:
                fp_key.write(self.keyfile)

        # updating .pi file to add new UUID
        self.stories.append(Story(new_uuid))
        self.update_pack_index()

        return True
    
    def import_flam_7z(self, story_path):
        # checking if archive is OK
        try:
            with py7zr.SevenZipFile(story_path, mode='r'):
                pass  # If opening succeeds, the archive is valid
        except py7zr.exceptions.Bad7zFile as e:
            self.signal_logger.emit(logging.ERROR, e)
            return False

        # opening zip file
        with py7zr.SevenZipFile(story_path, mode='r') as zip:
            # reading all available files
            zip_contents = zip.getnames()
            if story_is_lunii(zip_contents) or story_is_studio(zip_contents):
                self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "Archive seems to be made of Lunii story (Flam story expected)"))
                return False

            # reading all available files
            zip_contents = zip.list()

            # checking for keyfile
            storykeys_file = [entry for entry in zip_contents if entry.filename.endswith("bt")]
            if storykeys_file:
                self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Transciphering Flam story"))
                dict = zip.read([storykeys_file[0].filename])
                data = dict[storykeys_file[0].filename].read()
                story_key = data[:16]
                story_iv = data[16:]
            else:
                keyfile = [entry for entry in zip_contents if entry.filename.endswith("key")]
                if not keyfile:
                    self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "Flam story backup is incomplete, missing key file."))
                    return False
                self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Restoring Flam story backup"))

        # reopening zip file (SevenZip must work sequentially)
        with py7zr.SevenZipFile(story_path, mode='r') as zip:
            # reading all available files
            zip_contents = zip.list()

            # getting UUID from path
            uuid_path = Path(zip_contents[0].filename)
            uuid_str = uuid_path.parents[0].name if uuid_path.parents[0].name else uuid_path.name
            if len(uuid_str) >= 16:  # long enough to be a UUID
                # self.signal_logger.emit(logging.DEBUG, uuid_str)
                try:
                    if "-" not in uuid_str:
                        new_uuid = UUID(bytes=binascii.unhexlify(uuid_str))
                    else:
                        new_uuid = UUID(uuid_str)
                except ValueError as e:
                    self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "UUID parse error {}").format(e))
                    return False
            else:
                self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "UUID directory is missing in archive !"))
                return False

            # checking if UUID already loaded
            if str(new_uuid) in self.stories:
                self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "'{}' is already loaded, aborting !").format(self.stories.get_story(new_uuid).name))
                return False

            # decompressing story contents
            short_uuid = str(new_uuid).upper()[28:]
            output_path = Path(self.mount_point).joinpath(f"{self.STORIES_BASEDIR}")
            if not output_path.exists():
                output_path.mkdir(parents=True)

            # Loop over each file
            self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Reading 7zip archive... (takes time)"))
            contents = zip.readall().items()
            for index, (fname, bio) in enumerate(contents):

                # abort requested ? early exit
                if self.abort_process:
                    self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "Import aborted, performing cleanup on current story..."))
                    self.__clean_up_story_dir(new_uuid)
                    return False

                self.signal_story_progress.emit(short_uuid, index, len(contents))

                # Extract each zip file
                data = bio.read()

                self.signal_logger.emit(logging.DEBUG, f"File {index+1}/{len(contents)} > {fname}")

                # transcoding if necessary
                if storykeys_file:
                    if fname.endswith(".lsf") or fname.endswith("info"):
                        self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate("FlamDevice", "Transciphering file {}").format(fname))
                        # decipher
                        data_plain = aes_decipher(data, story_key, story_iv, 0, len(data))
                        # cipher
                        data = self.__get_ciphered_data(fname, data_plain, True, True)

                target: Path = output_path.joinpath(fname)

                # create target directory
                if not target.parent.exists():
                    target.parent.mkdir(parents=True)
                # write target file
                self.__write_with_progress(target, data)

        # keyfile creation due to transciphering
        if storykeys_file:
            self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Authorization file creation..."))
            new_keyfile = os.path.join(output_path, str(new_uuid), "key")
            with open(new_keyfile, "wb") as fp_key:
                fp_key.write(self.keyfile)

        # updating .pi file to add new UUID
        self.stories.append(Story(new_uuid))
        self.update_pack_index()

        return True

    def import_lunii_flam_zip(self, story_path):
        # extract filename and check if it starts with snu and snu is the same as the current device
        filename = os.path.basename(story_path)
        if not filename.lower().startswith(self.snu_str):
            self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "Lunii story from Flam personnal backup can't be imported on this device (SNU mismatch)."))
            return False

        night_mode = False
        self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Restoring Lunii story from Flam personnal backup..."))

        # checking if archive is OK
        try:
            with zipfile.ZipFile(file=story_path):
                pass  # If opening succeeds, the archive is valid
        except zipfile.BadZipFile as e:
            self.signal_logger.emit(logging.ERROR, e)
            return False
        
        # opening zip file
        with zipfile.ZipFile(file=story_path) as zip_file:
            # reading all available files
            zip_contents = zip_file.namelist()

            # getting UUID from path
            uuid_path = Path(zip_contents[0])
            uuid_str = uuid_path.parents[0].name if uuid_path.parents[0].name else uuid_path.name
            if len(uuid_str) >= 16:  # long enough to be a UUID
                # self.signal_logger.emit(logging.DEBUG, uuid_str)
                try:
                    if "-" not in uuid_str:
                        new_uuid = UUID(bytes=binascii.unhexlify(uuid_str))
                    else:
                        new_uuid = UUID(uuid_str)
                except ValueError as e:
                    self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "UUID parse error {}").format(e))
                    return False
            else:
                self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "UUID directory is missing in archive !"))
                return False

            # checking if UUID already loaded
            if str(new_uuid) in self.stories:
                self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "'{}' is already loaded !").format(self.stories.get_story(new_uuid).name))
                return False

            # decompressing story contents
            output_path = Path(self.mount_point).joinpath(self.STORIES_BASEDIR)
            # {str(new_uuid).upper()[28:]
            if not output_path.exists():
                output_path.mkdir(parents=True)

            # Loop over each file
            short_uuid = str(new_uuid).upper()[28:]
            for index, file in enumerate(zip_contents):
                self.signal_story_progress.emit(short_uuid, index, len(zip_contents))
                # abort requested ? early exit
                if self.abort_process:
                    self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "Import aborted, performing cleanup on current story..."))
                    self.__clean_up_story_dir(new_uuid)
                    return False

                if zip_file.getinfo(file).is_dir():
                    continue
                if file.endswith("nm"):
                    night_mode = True

                # Extract each zip file
                data = zip_file.read(file)
                target: Path = output_path.joinpath(file)

                # create target directory
                if not target.parent.exists():
                    target.parent.mkdir(parents=True)
                # write target file
                self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate("FlamDevice", "File {}/{} > {}").format(index+1, len(zip_contents), file))
                self.__write_with_progress(target, data)

        # updating .pi file to add new UUID
        self.stories.append(Story(new_uuid, nm=night_mode))
        self.update_pack_index()

        return True
    
    def import_lunii_v2_zip(self, story_path):
        night_mode = False

        # checking if archive is OK
        try:
            with zipfile.ZipFile(file=story_path):
                pass  # If opening succeeds, the archive is valid
        except zipfile.BadZipFile as e:
            self.signal_logger.emit(logging.ERROR, e)
            return False
        
        # opening zip file
        with zipfile.ZipFile(file=story_path) as zip_file:
            # reading all available files
            zip_contents = zip_file.namelist()
            if FILE_STUDIO_JSON in zip_contents:
                self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "Corrupted file format. Unable to add this story."))
                return False
      
            # getting UUID from path
            uuid_path = Path(zip_contents[0])
            uuid_str = uuid_path.parents[0].name if uuid_path.parents[0].name else uuid_path.name
            if len(uuid_str) >= 16:  # long enough to be a UUID
                try:
                    if "-" not in uuid_str:
                        new_uuid = UUID(bytes=binascii.unhexlify(uuid_str))
                    else:
                        new_uuid = UUID(uuid_str)
                except ValueError as e:
                    self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "UUID parse error {}").format(e))
                    return False
            else:
                self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "UUID directory is missing in archive !"))
                return False
            
            # checking if UUID already loaded
            if str(new_uuid) in self.stories:
                self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "'{}' is already loaded !").format(self.stories.get_story(new_uuid).name))
                return False

            # decompressing story contents
            long_uuid = str(new_uuid).lower()
            short_uuid = long_uuid[28:]
            output_path = Path(self.mount_point).joinpath(f"{self.STORIES_BASEDIR}")
            if not output_path.exists():
                output_path.mkdir(parents=True)

            # Loop over each file
            for index, file in enumerate(zip_contents):
                self.signal_story_progress.emit(short_uuid, index, len(zip_contents))
                # abort requested ? early exit
                if self.abort_process:
                    self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "Import aborted, performing cleanup on current story..."))
                    self.__clean_up_story_dir(new_uuid)
                    return False
                
                if zip_file.getinfo(file).is_dir():
                    continue
                if file == FILE_UUID or file.endswith("bt"):
                    continue
                if file.endswith("nm"):
                    night_mode = True

                # Extract each zip file
                data_v2 = zip_file.read(file)

                # need to transcipher ?
                if file.endswith("ni") or file.endswith("nm"):
                    # plain files
                    data_plain = data_v2
                else:
                    # to be deciphered
                    data_plain = xxtea_decipher(data_v2, lunii_generic_key, 0, 512)
                # updating filename, and ciphering header if necessary
                data = self.__get_ciphered_data(file, data_plain, False)

                file_newname = self.__get_lunii_ciphered_name(file.replace(uuid_str, str(new_uuid)))
                target: Path = output_path.joinpath(file_newname)

                # create target directory
                if not target.parent.exists():
                    target.parent.mkdir(parents=True)
                # write target file
                self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate("FlamDevice", "File {}/{} > {}").format(index+1, len(zip_contents), file_newname))
                self.__write_with_progress(target, data)

        # creating authorization file : bt
        self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Authorization file creation..."))
        story_path = output_path.joinpath(long_uuid)
        bt_path = story_path.joinpath("key")
        with open(bt_path, "wb") as fp_bt:
            fp_bt.write(self.keyfile)

        # story creation
        loaded_story = Story(new_uuid, nm=night_mode)

        # creating info file creation
        self.__write_info(loaded_story, story_path)

        # creating thumbnail image
        self.__write_thumbnail(loaded_story, story_path)

        # updating .pi file to add new UUID
        self.stories.append(loaded_story)
        self.update_pack_index()

        return True

    def import_lunii_v2_7z(self, story_path):
        night_mode = False

        # checking if archive is OK
        try:
            with py7zr.SevenZipFile(story_path, mode='r'):
                pass  # If opening succeeds, the archive is valid
        except py7zr.exceptions.Bad7zFile as e:
            self.signal_logger.emit(logging.ERROR, e)
            return False

        # opening zip file
        with py7zr.SevenZipFile(story_path, mode='r') as zip:
            # reading all available files
            archive_contents = zip.list()

            # getting UUID from path
            uuid_path = Path(archive_contents[0].filename)
            uuid_str = uuid_path.parents[0].name if uuid_path.parents[0].name else uuid_path.name
            if len(uuid_str) >= 16:  # long enough to be a UUID
                try:
                    if "-" not in uuid_str:
                        new_uuid = UUID(bytes=binascii.unhexlify(uuid_str))
                    else:
                        new_uuid = UUID(uuid_str)
                except ValueError as e:
                    self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "UUID parse error {}").format(e))
                    return False
            else:
                self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "UUID directory is missing in archive !"))
                return False

            # checking if UUID already loaded
            if str(new_uuid) in self.stories:
                self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "'{}' is already loaded !").format(self.stories.get_story(new_uuid).name))
                return False
            
            # decompressing story contents
            output_path = Path(self.mount_point).joinpath(self.STORIES_BASEDIR)
            # {str(new_uuid).upper()[28:]
            if not output_path.exists():
                output_path.mkdir(parents=True)

            # Loop over each file
            long_uuid = str(new_uuid).lower()
            short_uuid = long_uuid[28:]
            contents = zip.readall().items()
            for index, (fname, bio) in enumerate(contents):
                self.signal_story_progress.emit(short_uuid, index, len(contents))
                # abort requested ? early exit
                if self.abort_process:
                    self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "Import aborted, performing cleanup on current story..."))
                    self.__clean_up_story_dir(new_uuid)
                    return False

                if fname.endswith("bt"):
                    continue
                if fname.endswith("nm"):
                    night_mode = True

                # Extract each zip file
                data_v2 = bio.read()
                file = fname

                if self.device_version <= LUNII_V2:
                    # from v2 to v2, data can be kept as it is
                    data = data_v2
                else:
                    # need to transcipher for v3 ?
                    if file.endswith("ni") or file.endswith("nm"):
                        # plain files
                        data_plain = data_v2
                    else:
                        # to be ciphered
                        data_plain = xxtea_decipher(data_v2, lunii_generic_key, 0, 512)
                    # updating filename, and ciphering header if necessary
                    data = self.__get_ciphered_data(file, data_plain, False)

                file_newname = self.__get_lunii_ciphered_name(file.replace(uuid_str, str(new_uuid)))
                target: Path = output_path.joinpath(file_newname)

                # create target directory
                if not target.parent.exists():
                    target.parent.mkdir(parents=True)
                # write target file
                self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate("FlamDevice", "File {}/{} > {}").format(index+1, len(contents), file_newname))
                self.__write_with_progress(target, data)

        # creating authorization file : bt
        self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Authorization file creation..."))
        story_path = output_path.joinpath(long_uuid)
        bt_path = story_path.joinpath("key")
        with open(bt_path, "wb") as fp_bt:
            fp_bt.write(self.keyfile)

        # story creation
        loaded_story = Story(new_uuid, nm=night_mode)

        # creating info file creation
        self.__write_info(loaded_story, story_path)
        
        # creating thumbnail image
        self.__write_thumbnail(loaded_story, story_path)

        # updating .pi file to add new UUID
        self.stories.append(loaded_story)
        self.update_pack_index()

        return True

    def import_studio_zip(self, story_path):
        # checking if archive is OK
        try:
            with zipfile.ZipFile(file=story_path):
                pass  # If opening succeeds, the archive is valid
        except zipfile.BadZipFile as e:
            self.signal_logger.emit(logging.ERROR, e)
            return False
        
        # opening zip file
        with zipfile.ZipFile(file=story_path) as zip_file:
            # reading all available files
            zip_contents = zip_file.namelist()
            if FILE_UUID in zip_contents:
                self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "plain.pk format detected ! Unable to add this story."))
                return False
            if FILE_STUDIO_JSON not in zip_contents:
                self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "missing 'story.json'. Unable to add this story."))
                return False

            # getting UUID file
            try:
                story_json = json.loads(zip_file.read(FILE_STUDIO_JSON))
            except ValueError as e:
                self.signal_logger.emit(logging.ERROR, e)
                return False

            studio_story = StudioStory(story_json)
            if not studio_story.compatible:
                self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "STUdio story with non MP3 audio file. You need FFMPEG tool to import such kind of story, refer to README.md"))
                return False

            stories.thirdparty_db_add_story(studio_story.uuid, studio_story.title, studio_story.description)

            # checking if UUID already loaded
            if str(studio_story.uuid) in self.stories:
                self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "'{}' is already loaded !").format(studio_story.name))
                return False

            # decompressing story contents
            long_uuid = str(studio_story.uuid).lower()
            short_uuid = studio_story.short_uuid
            output_path = Path(self.mount_point).joinpath(f"{self.STORIES_BASEDIR}{long_uuid}")
            if not output_path.exists():
                output_path.mkdir(parents=True)

            # Loop over each file
            for index, file in enumerate(zip_contents):
                self.signal_story_progress.emit(short_uuid, index, len(zip_contents))
                # abort requested ? early exit
                if self.abort_process:
                    self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "Import aborted, performing cleanup on current story..."))
                    self.__clean_up_story_dir(studio_story.uuid)
                    return False

                if zip_file.getinfo(file).is_dir():
                    continue
                if file.endswith(FILE_STUDIO_JSON):
                    continue
                if file.endswith(FILE_STUDIO_THUMB):
                    # adding thumb to DB
                    data = zip_file.read(file)
                    stories.thirdparty_db_add_thumb(studio_story.uuid, data)
                    continue
                if not file.startswith("assets"):
                    continue

                # Extract each zip file
                data = zip_file.read(file)

                # stripping extra "assets/" chars
                file = file[7:]
                if file in studio_story.ri:
                    file_newname = self.__get_lunii_ciphered_name(studio_story.ri[file][0], studio_ri=True)
                    # transcode image if necessary
                    data = image_to_bitmap_rle4(data)
                elif file in studio_story.si:
                    file_newname = self.__get_lunii_ciphered_name(studio_story.si[file][0], studio_si=True)
                    # transcode audio if necessary
                    if transcoding_required(file, data):
                        if not STORY_TRANSCODING_SUPPORTED:
                            self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "STUdio story with non MP3 audio file. You need FFMPEG tool to import such kind of story, refer to README.md"))
                            return False

                        self.signal_logger.emit(logging.WARN, QCoreApplication.translate("FlamDevice", "⌛ Transcoding audio {} : {:4} KB ...").format(file_newname, len(data)//1024))
                        # len_before = len(data)//1024
                        self.signal_file_progress.emit(f"⌛ FFMPEG", 0, 0)
                        data = audio_to_mp3(data)
                        self.signal_file_progress.emit(f"", 0, 0)
                        # print(f"Transcoded from {len_before:4}KB to {len(data)//1024:4}KB")
                    # removing tags if necessary
                    if tags_removal_required(data):
                        self.signal_logger.emit(logging.WARN, QCoreApplication.translate("FlamDevice", "⌛ Removing tags from audio {}").format(file_newname))
                        data = mp3_tag_cleanup(data)

                else:
                    # unexpected file, skipping
                    continue

                # updating filename, and ciphering header if necessary
                data_ciphered = self.__get_ciphered_data(file, data, False)
                target: Path = output_path.joinpath(file_newname)

                # create target directory
                if not target.parent.exists():
                    target.parent.mkdir(parents=True)
                # write target file
                self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate("FlamDevice", "File {}/{} > {}").format(index+1, len(zip_contents), file_newname))
                self.__write_with_progress(target, data_ciphered)

        # creating lunii index files : ri
        ri_data = studio_story.get_ri_data()
        self.__write(ri_data, output_path, "ri")

        # creating lunii index files : si, ni, li
        self.__write(studio_story.get_si_data(), output_path, "si")
        self.__write(studio_story.get_li_data(), output_path, "li")
        self.__write(studio_story.get_ni_data(), output_path, "ni")

        # creating authorization file : key
        self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Authorization file creation..."))
        key_path = output_path.joinpath("key")
        with open(key_path, "wb") as fp_key:
            fp_key.write(self.keyfile)

        # creating night mode file
        if studio_story.nm:
            self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Night mode file creation..."))
            # creating empty nm file
            with open(output_path.joinpath("nm"), "wb") as fp_nm:
                pass
                
        # story creation
        one_story = Story(studio_story.uuid, nm = studio_story.nm)

        # creating info file creation
        self.__write_info(one_story, output_path)

        # creating thumbnail image
        self.__write_thumbnail(one_story, output_path)

        # updating .pi file to add new UUID
        self.stories.append(one_story)
        self.update_pack_index()

        return True

    def import_studio_7z(self, story_path):
        # checking if archive is OK
        try:
            with py7zr.SevenZipFile(story_path, mode='r'):
                pass  # If opening succeeds, the archive is valid
        except py7zr.exceptions.Bad7zFile as e:
            self.signal_logger.emit(logging.ERROR, e)
            return False

        # opening zip file
        with py7zr.SevenZipFile(story_path, mode='r') as zip:
            # reading all available files
            zip_contents = zip.readall()
            if FILE_UUID in zip_contents:
                self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "plain.pk format detected ! Unable to add this story."))
                return False
            if FILE_STUDIO_JSON not in zip_contents:
                self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "missing 'story.json'. Unable to add this story."))
                return False
  
            # getting UUID file
            try:
                story_json = json.loads(zip_contents[FILE_STUDIO_JSON].read())
            except ValueError as e:
                self.signal_logger.emit(logging.ERROR, e)
                return False

            studio_story = StudioStory(story_json)
            if not studio_story.compatible:
                self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "STUdio story with non MP3 audio file. You need FFMPEG tool to import such kind of story, refer to README.md"))
                return False

            stories.thirdparty_db_add_story(studio_story.uuid, studio_story.title, studio_story.description)

            # checking if UUID already loaded
            if str(studio_story.uuid) in self.stories:
                self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "'{}' is already loaded !").format(studio_story.name))
                return False

            # decompressing story contents
            long_uuid = str(studio_story.uuid).lower()
            short_uuid = studio_story.short_uuid
            output_path = Path(self.mount_point).joinpath(f"{self.STORIES_BASEDIR}{long_uuid}")
            if not output_path.exists():
                output_path.mkdir(parents=True)

            # Loop over each file
            contents = zip_contents.items()
            for index, (fname, bio) in enumerate(contents):
                self.signal_story_progress.emit(short_uuid, index, len(contents))
                # abort requested ? early exit
                if self.abort_process:
                    self.signal_logger.emit(logging.WARNING, QCoreApplication.translate("FlamDevice", "Import aborted, performing cleanup on current story..."))
                    self.__clean_up_story_dir(studio_story.uuid)
                    return False

                if fname.endswith(FILE_STUDIO_JSON):
                    continue
                if fname.endswith(FILE_STUDIO_THUMB):
                    # adding thumb to DB
                    data = bio.read()
                    stories.thirdparty_db_add_thumb(studio_story.uuid, data)
                    continue
                if not fname.startswith("assets"):
                    continue

                # Extract each zip file
                data = bio.read()

                # stripping extra "assets/" chars
                fname = fname[7:]
                if fname in studio_story.ri:
                    file_newname = self.__get_lunii_ciphered_name(studio_story.ri[fname][0], studio_ri=True)
                    # transcode image if necessary
                    data = image_to_bitmap_rle4(data)
                elif fname in studio_story.si:
                    file_newname = self.__get_lunii_ciphered_name(studio_story.si[fname][0], studio_si=True)
                    # transcode audio if necessary
                    if transcoding_required(fname, data):
                        if not STORY_TRANSCODING_SUPPORTED:
                            self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "STUdio story with non MP3 audio file. You need FFMPEG tool to import such kind of story, refer to README.md"))
                            return False

                        self.signal_logger.emit(logging.WARN, QCoreApplication.translate("FlamDevice", "⌛ Transcoding audio {} : {:4} KB ...").format(file_newname, len(data)//1024))
                        self.signal_file_progress.emit(f"⌛ FFMPEG", 0, 0)
                        data = audio_to_mp3(data)
                        self.signal_file_progress.emit(f"", 0, 0)
                else:
                    # unexpected file, skipping
                    continue

                # updating filename, and ciphering header if necessary
                data_ciphered = self.__get_ciphered_data(fname, data, False)
                target: Path = output_path.joinpath(file_newname)

                # create target directory
                if not target.parent.exists():
                    target.parent.mkdir(parents=True)
                # write target file
                self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate("FlamDevice", "File {}/{} > {}").format(index+1, len(contents), file_newname))
                self.__write_with_progress(target, data_ciphered)

        # creating lunii index files : ri
        ri_data = studio_story.get_ri_data()
        self.__write(ri_data, output_path, "ri")

        # creating lunii index files : si, ni, li
        self.__write(studio_story.get_si_data(), output_path, "si")
        self.__write(studio_story.get_li_data(), output_path, "li")
        self.__write(studio_story.get_ni_data(), output_path, "ni")

        # creating authorization file : key
        self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Authorization file creation..."))
        key_path = output_path.joinpath("key")
        with open(key_path, "wb") as fp_key:
            fp_key.write(self.keyfile)

        # creating night mode file
        if studio_story.nm:
            self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Night mode file creation..."))
            # creating empty nm file
            with open(output_path.joinpath("nm"), "wb") as fp_nm:
                pass

        # story creation
        one_story = Story(studio_story.uuid, nm = studio_story.nm)

        # creating info file creation
        self.__write_info(one_story, output_path)

        # creating thumbnail image
        self.__write_thumbnail(one_story, output_path)

        # updating .pi file to add new UUID
        self.stories.append(one_story)
        self.update_pack_index()

        return True

    def __write_info(self, one_story, output_path):
        info_path = output_path.joinpath("info")

        story_name = unidecode(one_story.name)
        story_author = unidecode(one_story.author)

        with open(info_path, "w") as fp_info:
            fp_info.write(f"{story_name}\n")
            fp_info.write(f"{story_name}\n")
            fp_info.write("0\n")
            fp_info.write(f"{story_name}\n")
            fp_info.write(story_author)

    def __write_thumbnail(self, one_story, output_path):
        thumb_path = output_path.joinpath("img")
        thumb_path.mkdir(parents=True, exist_ok=True)
        thumb_path = thumb_path.joinpath("thumbnail.lif")

        with open(thumb_path, "wb") as fp:
            data = one_story.get_picture()
            lif_data = image_to_liff(data)
            fp.write(lif_data)

    def __write(self, data_plain, output_path, file):
        path_file = os.path.join(output_path, file)
        with open(path_file, "wb") as fp:
            data = self.__get_ciphered_data(path_file, data_plain, False)
            # data =  data_plain
            fp.write(data)

    def __write_with_progress(self, target, data):
        time_span_s = 0.250
        block_size = 10 * 1024  # 10KB

        total_size = len(data)
        written = 0
        start_time = last_emit = time.time()
        last_written = 0

        fname = os.path.basename(target)

        with open(target, "wb") as f_dst:
            while written < total_size:
                chunk = data[written:written + block_size]
                f_dst.write(chunk)
                written += len(chunk)
                now = time.time()
                if now - last_emit >= time_span_s or written == total_size:
                    elapsed = now - last_emit
                    speed = ((written - last_written) / elapsed) // 1024 if elapsed > 0 else 0

                    self.signal_file_progress.emit(f"{speed:,} KB/s", written, total_size)
                    self.signal_logger.emit(
                        logging.DEBUG,
                        f"Progress on {fname} - {written:,} / {total_size:,} Bytes ( {speed:,} KB/s )"
                    )
                    last_emit = now
                    last_written = written

    def export_backup_story(self, one_story, out_path):
        story_path = os.path.join(self.mount_point, self.STORIES_BASEDIR if not one_story.hidden else self.HIDDEN_STORIES_BASEDIR, str(one_story.uuid))
        self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "🚧 Exporting {} - {}").format(one_story.short_uuid, one_story.name))

        # Preparing zip file
        sname = one_story.name
        sname = secure_filename(sname)

        zip_path = Path(out_path).joinpath(f"{self.snu_str}.{sname}.{one_story.short_uuid}.zip")
        # if os.path.isfile(zip_path):
        #     self.signal_logger.emit(logging.WARNING, f"Already exported")
        #     return None

        # preparing file list
        story_flist = []
        story_arcnames = []
        for root, _, filenames in os.walk(story_path):
            for filename in filenames:
                abs_file = os.path.join(root, filename)
                story_flist.append(abs_file)

                index = abs_file.find(str(one_story.uuid))
                story_arcnames.append(abs_file[index:])

        try:
            with zipfile.ZipFile(zip_path, 'w') as zip_out:
                self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate("FlamDevice", "> Zipping story ..."))
                for index, file in enumerate(story_flist):
                    # abort requested ? early exit
                    if self.abort_process:
                        return None

                    self.signal_story_progress.emit(one_story.short_uuid, index, len(story_flist))
                    self.signal_logger.emit(logging.DEBUG, story_arcnames[index])
                    zip_out.write(file, story_arcnames[index])

        except PermissionError as e:
            self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "failed to create ZIP - {}").format(e))
            return None

        return zip_path
    
    def export_flam_plainstory(self, one_story, out_path, story_key, story_iv):
        story_path = os.path.join(self.mount_point, self.STORIES_BASEDIR if not one_story.hidden else self.HIDDEN_STORIES_BASEDIR, str(one_story.uuid))
        self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "🚧 Exporting {} - {}").format(one_story.uuid, one_story.name))

        # Preparing zip file
        sname = one_story.name
        sname = secure_filename(sname)

        zip_path = Path(out_path).joinpath(f"{sname}.{one_story.short_uuid}.plain.pk")
        # if os.path.isfile(zip_path):
        #     self.signal_logger.emit(logging.WARNING, f"Already exported")
        #     return None
        
        # preparing file list
        story_flist = []
        story_arcnames = []
        for root, _, filenames in os.walk(story_path):
            for filename in filenames:
                # skipping some of them
                if filename in ["key", "bt"]:
                    continue

                abs_file = os.path.join(root, filename)

                # source files list
                story_flist.append(abs_file)

                # target file in zip
                file = abs_file.split(str(one_story.uuid).lower())[1]
                while file.startswith("\\") or file.startswith("/"):
                    file = file[1:]

                if file.endswith(".lsf"):
                    file = file.replace(".lsf", ".lua")
                if file.endswith("info"):
                    file += ".plain"
                    
                story_arcnames.append(file)

        try:
            with zipfile.ZipFile(zip_path, 'w') as zip_out:
                self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate("FlamDevice", "> Zipping story ..."))
                for index, file in enumerate(story_flist):
                    self.signal_story_progress.emit(one_story.short_uuid, index, len(story_flist))
                    # abort requested ? early exit
                    if self.abort_process:
                        return None

                    # target file 
                    target_file = story_arcnames[index]

                    # Extract each file to another directory
                    # decipher if necessary (*.lsf / info)
                    with open(file, "rb") as fp:
                        data = fp.read()
                    if file.endswith(".lsf") or file.endswith("info"):
                        data = aes_decipher(data, story_key, story_iv, 0, len(data))

                    zip_out.writestr(target_file, data)

                # adding uuid file
                self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate("FlamDevice", "> Adding UUID ..."))
                zip_out.writestr(FILE_UUID, one_story.uuid.bytes)

        except PermissionError as e:
            self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "failed to create ZIP - {}").format(e))
            return None
        
        return zip_path

    def export_lunii_plainstory(self, one_story, out_path, story_key, story_iv):
        story_path = os.path.join(self.mount_point, self.STORIES_BASEDIR if not one_story.hidden else self.HIDDEN_STORIES_BASEDIR, str(one_story.uuid))
        self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "🚧 Exporting {} - {}").format(one_story.uuid, one_story.name))

        # Preparing zip file
        sname = one_story.name
        sname = secure_filename(sname)

        zip_path = Path(out_path).joinpath(f"{sname}.{one_story.short_uuid}.plain.pk")
        # if os.path.isfile(zip_path):
        #     self.signal_logger.emit(logging.WARNING, f"Already exported")
        #     return None
        
        # preparing file list
        story_flist = []
        story_arcnames = []
        for root, _, filenames in os.walk(story_path):
            if "img" in root:
                continue

            for filename in filenames:
                # skipping some of them
                if filename in ["key", "bt", "info"]:
                    continue

                abs_file = os.path.join(root, filename)

                # source files list
                story_flist.append(abs_file)

                # target file in zip
                file = abs_file.split(str(one_story.uuid).lower())[1]
                while file.startswith("\\") or file.startswith("/"):
                    file = file[1:]

                if "rf/" in file or "rf\\" in file:
                    file = file+".bmp"
                if "sf/" in file or "sf\\" in file:
                    file = file+".mp3"
                if file.endswith("li") or file.endswith("ri") or file.endswith("si"):
                    file = file+".plain"
                    
                story_arcnames.append(file)

        try:
            with zipfile.ZipFile(zip_path, 'w') as zip_out:
                self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate("FlamDevice", "> Zipping story ..."))
                for index, file in enumerate(story_flist):
                    self.signal_story_progress.emit(one_story.short_uuid, index, len(story_flist))
                    # abort requested ? early exit
                    if self.abort_process:
                        return None

                    # target file 
                    target_file = story_arcnames[index]

                    # Extract each file to another directory
                    with open(file, "rb") as fp:
                        data = fp.read()
                    if target_file.endswith(".mp3") or target_file.endswith(".bmp") or target_file.endswith(".plain"):
                        data = aes_decipher(data, story_key, story_iv, 0, 0x200)

                    zip_out.writestr(target_file, data)

                # adding uuid file
                self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate("FlamDevice", "> Adding UUID ..."))
                zip_out.writestr(FILE_UUID, one_story.uuid.bytes)

                # more files to be added for thirdparty stories
                if not one_story.is_official():
                    self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate("FlamDevice", "> Adding thumbnail ..."))
                    pict_data = one_story.get_picture()
                    if pict_data:
                        zip_out.writestr(FILE_THUMB, pict_data)

                    self.signal_logger.emit(logging.DEBUG, QCoreApplication.translate("FlamDevice", "> Adding metadata ..."))
                    meta = one_story.get_meta()
                    if meta:
                        zip_out.writestr(FILE_META, meta)

        except PermissionError as e:
            self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "failed to create ZIP - {}").format(e))
            return None
        
        return zip_path

    def __find_shared_bt(self, key_data, skip_uuid):
        # The bt file (transcipher key + iv) is shared by every story belonging
        # to the same owner, identified by an identical "key" file. When a story
        # is missing its bt, look for a sibling story (same key, different uuid)
        # that still has one and return its 32 bytes (key + iv).
        for basedir in (self.STORIES_BASEDIR, self.HIDDEN_STORIES_BASEDIR):
            base_path = os.path.join(self.mount_point, basedir)
            if not os.path.isdir(base_path):
                continue
            for entry in os.listdir(base_path):
                if entry == str(skip_uuid):
                    continue
                sibling_key = os.path.join(base_path, entry, "key")
                sibling_bt = os.path.join(base_path, entry, "bt")
                if not (os.path.isfile(sibling_key) and os.path.isfile(sibling_bt)):
                    continue
                with open(sibling_key, "rb") as fp_key:
                    if fp_key.read() != key_data:
                        continue
                with open(sibling_bt, "rb") as fp_bt:
                    bt_data = fp_bt.read(32)
                if len(bt_data) == 32:
                    return bt_data
        return None

    def export_story(self, uuid, out_path):
        # is UUID part of existing stories
        slist = self.stories.matching_stories(uuid)
        if len(slist) > 1:
            self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "at least {} match your pattern. Try a longer UUID.").format(len(slist)))
            for st in slist:
                self.signal_logger.emit(logging.ERROR, f"[{st.str_uuid} - {st.name}]")
            return None

        one_story = slist[0]

        # is story path existing ?
        story_path = os.path.join(self.mount_point, self.STORIES_BASEDIR if not one_story.hidden else self.HIDDEN_STORIES_BASEDIR, str(uuid))

        if os.path.isdir(story_path):
            # list all files in story directory including subdirs using glob
            story_files = glob(os.path.join(story_path, "**"), recursive=True)

            # checking for known keys ?
            exportable = False
            # reading keyfile in story and compare with known keys
            story_keyfile = os.path.join(story_path, "key")
            if os.path.isfile(story_keyfile):  
                with open(story_keyfile, "rb") as fp_key:
                    story_keydata = fp_key.read()
                    exportable = (story_keydata == self.keyfile)
                    story_key = self.story_key
                    story_iv = self.story_iv
            # checking for bt file exists in flam stories
            story_btfile = os.path.join(story_path, "bt")
            if not exportable and os.path.isfile(story_btfile):
                exportable = True
                with open(story_btfile, "rb") as fp_bt:
                    story_key = fp_bt.read(16)
                    story_iv = fp_bt.read(16)

            # bt may be missing for some stories while another story sharing the
            # same owner (same "key" file) still carries it. The bt (transcipher
            # key) is shared across all stories of a given owner, so we can borrow
            # it from a sibling story to export this one as plain.
            if not exportable and os.path.isfile(story_keyfile):
                shared_bt = self.__find_shared_bt(story_keydata, one_story.uuid)
                if shared_bt:
                    exportable = True
                    story_key = shared_bt[:16]
                    story_iv = shared_bt[16:32]
                    self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "Missing bt, reusing transcipher key from a sibling story"))

            if not exportable:
                return self.export_backup_story(one_story, out_path)
            else:
                if story_is_flam(story_files):
                    return self.export_flam_plainstory(one_story, out_path, story_key, story_iv)
                elif story_is_lunii(story_files):
                    return self.export_lunii_plainstory(one_story, out_path, reverse_bytes(story_key), reverse_bytes(story_iv))
                else:
                    self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "This story format is not supported for export."))
        
        return None
    
    def __clean_up_story_dir(self, story_uuid: UUID):
        story_dir = Path(self.mount_point).joinpath(f"{self.STORIES_BASEDIR}{str(story_uuid)}")
        hidden_story_dir = Path(self.mount_point).joinpath(f"{self.HIDDEN_STORIES_BASEDIR}{str(story_uuid)}")
        try:
            if os.path.isdir(story_dir):
                shutil.rmtree(story_dir)
            if os.path.isdir(hidden_story_dir):
                shutil.rmtree(hidden_story_dir)
        except OSError as e:
            self.signal_logger.emit(logging.ERROR, e)
            return False
        except PermissionError as e:
            self.signal_logger.emit(logging.ERROR, e)
            return False
        return True

    def remove_story(self, short_uuid):
        if short_uuid not in self.stories:
            self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "This story is not present on your storyteller"))
            return False

        slist = self.stories.matching_stories(short_uuid)
        if len(slist) > 1:
            self.signal_logger.emit(logging.ERROR, QCoreApplication.translate("FlamDevice", "at least {} match your pattern. Try a longer UUID.").format(len(slist)))
            return False
        uuid = slist[0].str_uuid

        self.signal_logger.emit(logging.INFO, QCoreApplication.translate("FlamDevice", "🚧 Removing {} - {}...").format(uuid[28:], self.stories.get_story(uuid).name))

        short_uuid = uuid[28:]
        self.signal_story_progress.emit(short_uuid, 0, 3)

        # removing story contents
        if not self.__clean_up_story_dir(slist[0].uuid):
            return False

        self.signal_story_progress.emit(short_uuid, 1, 3)

        # removing story from class
        self.stories.remove(slist[0])
        # updating pack index file
        self.update_pack_index()

        self.signal_story_progress.emit(short_uuid, 2, 3)

        return True

    #TODO
    def factory_reset(self):
        print("factory_reset")
        pass


# opens the .pi file to read all installed stories
def feed_stories(root_path) -> StoryList[UUID]:
    logger = logging.getLogger(LUNII_LOGGER)

    mount_path = Path(root_path)
    list_path = mount_path.joinpath(LIB_BASEDIR + "list")
    list_hidden_path = mount_path.joinpath(LIB_BASEDIR + "list.hidden")

    story_list = StoryList()

    logger.log(logging.INFO, QCoreApplication.translate("FlamDevice", "Reading Flam loaded stories..."))

    # if there is a list
    if os.path.isfile(list_path):
        with open(list_path, "r") as fp_list:
            lines = fp_list.read().splitlines()
            for uuid_str in lines:
                one_uuid = UUID(uuid_str.strip())
                logger.log(logging.DEBUG, f"> {str(one_uuid)}")
                if one_uuid in story_list:
                    logger.log(logging.WARNING, QCoreApplication.translate("FlamDevice", "Found duplicate story, cleaning..."))
                else:
                    story_list.append(Story(one_uuid))

    story_count = len(story_list)
    logger.log(logging.INFO, QCoreApplication.translate("FlamDevice", "Read {} stories").format(len(story_list)))

    # if there is a hidden list
    if os.path.isfile(list_hidden_path):
        with open(list_hidden_path, "r") as fp_list:
            lines = fp_list.read().splitlines()
            for uuid_str in lines:
                one_uuid = UUID(uuid_str.strip())
                logger.log(logging.DEBUG, f"> {str(one_uuid)}")
                if one_uuid in story_list:
                    logger.log(logging.WARNING, QCoreApplication.translate("FlamDevice", "Found duplicate story, cleaning..."))
                else:
                    story_list.append(Story(one_uuid, True))

    logger.log(logging.INFO, QCoreApplication.translate("FlamDevice", "Read {} hidden stories").format(len(story_list) - story_count))
    return story_list


def is_flam(root_path):
    MDF_FILE = os.path.join(root_path, ".mdf")

    try:
        if os.path.isfile(MDF_FILE):
            return True
    except PermissionError:
        pass
    return False


