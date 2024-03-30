# -*- coding: utf-8 -*-

from os import makedirs
from os.path import join, basename
from sqlite3 import connect, Connection, Error
from weakref import finalize

from ida_diskio import get_user_idadir


class RevEngDatabase(object):
    _filename = ".reai.db"
    _dir = join(get_user_idadir(), "plugins")

    def __init__(self) -> None:
        makedirs(RevEngDatabase._dir, mode=0o755, exist_ok=True)

        self._finalizer = finalize(self, self._cleanup_files)

        try:
            self.conn: Connection = connect(join(self._dir, self._filename))

            self.create_tables()
        except Error:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._finalizer()

    def _cleanup_files(self):
        try:
            self.conn.close()
        except Error:
            pass

    def create_tables(self) -> None:
        try:
            cursor = self.conn.cursor()

            cursor.execute("""
                        CREATE TABLE IF NOT EXISTS upload(
                        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
                        sha_256_hash TEXT NOT NULL UNIQUE, name TEXT);
                        """)

            cursor.execute("""
                        CREATE TABLE IF NOT EXISTS analysis(
                        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
                        sha_256_hash TEXT NOT NULL, binary_id INTEGER NOT NULL UNIQUE, status TEXT, submitted TEXT);
                        """)
        except Error:
            pass
        finally:
            self.conn.commit()

    def drop_tables(self) -> None:
        try:
            cursor = self.conn.cursor()

            for table in ["upload", "analysis"]:
                cursor.execute(f"DROP TABLE {table}")
        except Error:
            pass
        finally:
            self.conn.commit()

    def add_upload(self, fpath: str, sha_256_hash: str) -> None:
        try:
            self.conn.cursor().execute("INSERT INTO upload(name, sha_256_hash) VALUES(?, ?)",
                                       (basename(fpath), sha_256_hash,))
        except Error:
            pass
        finally:
            self.conn.commit()

    def delete_upload(self, sha_256_hash: str) -> None:
        try:
            for table in ["upload", "analysis"]:
                self.conn.cursor().execute(f"DELETE FROM {table} WHERE sha_256_hash = ?",
                                           (sha_256_hash,))
        except Error:
            pass
        finally:
            self.conn.commit()

    def get_last_analysis(self, sha_256_hash) -> int:
        try:
            cursor = self.conn.cursor()

            cursor.execute("SELECT binary_id FROM analysis WHERE sha_256_hash = ? ORDER BY binary_id DESC",
                           (sha_256_hash,))

            return cursor.fetchone()
        except Error:
            pass

    def add_analysis(self, sha_256_hash: str, bid: int, status: str = "", submitted: str = "") -> None:
        try:
            self.conn.cursor().execute("INSERT OR REPLACE INTO analysis(sha_256_hash, binary_id, status, submitted) VALUES(?, ?, ?, ?)",
                                       (sha_256_hash, bid, status, submitted,))
        except Error:
            pass
        finally:
            self.conn.commit()

    def update_analysis(self, bid: int, status: str) -> None:
        try:
            self.conn.cursor().execute("UPDATE analysis SET status = ? WHERE binary_id = ?",
                                       (status, bid,))
        except Error:
            pass
        finally:
            self.conn.commit()

    def delete_analysis(self, bid: int) -> None:
        try:
            self.conn.cursor().execute("DELETE FROM analysis WHERE binary_id = ?",
                                       (bid,))
        except Error:
            pass
        finally:
            self.conn.commit()
