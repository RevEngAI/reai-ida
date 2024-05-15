# -*- coding: utf-8 -*-
import logging
from contextlib import closing

from os import makedirs
from os.path import join, basename
from sqlite3 import connect, Connection, Error
from weakref import finalize

from ida_diskio import get_user_idadir


logger = logging.getLogger("REAI")


class RevEngDatabase(object):
    _filename = ".reai.db"
    _dir = join(get_user_idadir(), "plugins")

    def __init__(self) -> None:
        makedirs(RevEngDatabase._dir, mode=0o755, exist_ok=True)

        self._finalizer = finalize(self, self._cleanup_files)

        try:
            self.conn: Connection = connect(join(self._dir, self._filename))

            self.create_tables()
        except Error as e:
            logger.error("Error connecting to local database. %s", e)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._finalizer()

    def _cleanup_files(self):
        try:
            self.conn.close()
        except Error as e:
            logger.error("Error closing the connecting to local database. %s", e)

    def create_tables(self) -> None:
        try:
            with closing(self.conn.cursor()) as cursor:
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS upload(
                id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
                sha_256_hash TEXT NOT NULL UNIQUE, name TEXT);
                """)

                cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis(
                id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
                sha_256_hash TEXT NOT NULL, binary_id INTEGER NOT NULL UNIQUE,
                status TEXT, creation TEXT, model_name TEXT);
                """)
        except Error as e:
            logger.error("Error creating tables to local database. %s", e)
        finally:
            self.conn.commit()

    def drop_tables(self) -> None:
        try:
            with closing(self.conn.cursor()) as cursor:
                for table in ("upload", "analysis",):
                    cursor.execute(f"DROP TABLE {table}")
        except Error as e:
            logger.error("Error dropping tables from local database. %s", e)
        finally:
            self.conn.commit()

    def add_upload(self, fpath: str, sha_256_hash: str) -> None:
        try:
            with closing(self.conn.cursor()) as cursor:
                cursor.execute("INSERT OR REPLACE INTO upload(name, sha_256_hash) VALUES(?, ?)",
                               (basename(fpath), sha_256_hash,))
        except Error as e:
            logger.error("Error adding upload into local database for hash: %s. %s", sha_256_hash, e)
        finally:
            self.conn.commit()

    def delete_upload(self, sha_256_hash: str) -> None:
        try:
            with closing(self.conn.cursor()) as cursor:
                for table in ("upload", "analysis",):
                    cursor.execute(f"DELETE FROM {table} WHERE sha_256_hash = ?", (sha_256_hash,))
        except Error as e:
            logger.error("Error deleting upload from local database for hash: %s. %s", sha_256_hash, e)
        finally:
            self.conn.commit()

    def get_last_analysis(self, sha_256_hash: str) -> int:
        try:
            with closing(self.conn.cursor()) as cursor:
                cursor.execute("SELECT binary_id FROM analysis WHERE sha_256_hash = ? ORDER BY binary_id DESC LIMIT 1",
                               (sha_256_hash,))

                result = cursor.fetchone()
                return result[0] if result and len(result) > 0 else 0
        except Error as e:
            logger.error("Error getting last analysis for hash: %s. %s", sha_256_hash, e)

    def add_analysis(self, sha_256_hash: str, bid: int, status: str = "", creation: str = "", model_name: str = "") -> None:
        try:
            with closing(self.conn.cursor()) as cursor:
                cursor.execute("INSERT OR REPLACE INTO analysis(sha_256_hash, binary_id, status, creation, model_name) VALUES(?, ?, ?, ?, ?)",
                               (sha_256_hash, bid, status, creation, model_name,))
        except Error as e:
            logger.error("Error adding analysis for bid: %d, status: %s, hash: %s. %s",
                         bid, status, sha_256_hash, e)
        finally:
            self.conn.commit()

    def update_analysis(self, bid: int, status: str) -> None:
        try:
            with closing(self.conn.cursor()) as cursor:
                cursor.execute("UPDATE analysis SET status = ? WHERE binary_id = ?", (status, bid,))
        except Error as e:
            logger.error("Error updating analysis for bid: %d, status: %s. %s", bid, status, e)
        finally:
            self.conn.commit()

    def delete_analysis(self, bid: int) -> None:
        try:
            with closing(self.conn.cursor()) as cursor:
                cursor.execute("DELETE FROM analysis WHERE binary_id = ?", (bid,))
        except Error as e:
            logger.error("Error deleting analysis from database for bid: %d. %s", bid, e)
        finally:
            self.conn.commit()
