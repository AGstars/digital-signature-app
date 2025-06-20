import sqlite3
from sqlite3 import Error
from typing import Tuple, List, Optional

class DatabaseManager:
    """数据库管理类"""
    def __init__(self, db_file: str):
        self.conn = self._create_connection(db_file)
        self._create_tables()
    
    def _create_connection(self, db_file: str) -> sqlite3.Connection:
        """创建数据库连接"""
        conn = None
        try:
            conn = sqlite3.connect(db_file)
            return conn
        except Error as e:
            print(e)
        return conn
    
    def _create_tables(self) -> None:
        """创建数据库表"""
        sql_create_users_table = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );
        """
        
        sql_create_keys_table = """
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            algorithm TEXT NOT NULL,
            private_key TEXT NOT NULL,
            public_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(user_id, algorithm)
        );
        """
        
        sql_create_signatures_table = """
        CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            key_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (key_id) REFERENCES keys (id)
        );
        """
        
        try:
            c = self.conn.cursor()
            c.execute(sql_create_users_table)
            c.execute(sql_create_keys_table)
            c.execute(sql_create_signatures_table)
            self.conn.commit()
        except Error as e:
            print(e)
    
    def add_user(self, username: str, password_hash: str) -> bool:
        """添加用户"""
        sql = """INSERT INTO users(username, password_hash) VALUES(?,?)"""
        try:
            cur = self.conn.cursor()
            cur.execute(sql, (username, password_hash))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        except Error as e:
            print(e)
            return False
    
    def get_user(self, username: str) -> Optional[Tuple[int, str, str]]:
        """获取用户"""
        sql = """SELECT * FROM users WHERE username = ?"""
        try:
            cur = self.conn.cursor()
            cur.execute(sql, (username,))
            return cur.fetchone()
        except Error as e:
            print(e)
            return None
    
    def add_key_pair(self, user_id: int, algorithm: str, private_key: str, public_key: str) -> int:
        """添加密钥对"""
        sql = """INSERT INTO keys(user_id, algorithm, private_key, public_key) VALUES(?,?,?,?)"""
        try:
            cur = self.conn.cursor()
            cur.execute(sql, (user_id, algorithm, private_key, public_key))
            self.conn.commit()
            return cur.lastrowid
        except Error as e:
            print(e)
            return -1
    
    def get_key_pair_by_algorithm(self, user_id: int, algorithm: str) -> Optional[Tuple[int, int, str, str, str, str]]:
        """根据用户ID和算法获取密钥对"""
        sql = """SELECT * FROM keys WHERE user_id = ? AND algorithm = ?"""
        try:
            cur = self.conn.cursor()
            cur.execute(sql, (user_id, algorithm))
            return cur.fetchone()
        except Error as e:
            print(e)
            return None

    def get_key_pair_by_id(self, key_id: int) -> Optional[Tuple[int, int, str, str, str, str]]:
        """根据密钥ID获取密钥对"""
        sql = """SELECT * FROM keys WHERE id = ?"""
        try:
            cur = self.conn.cursor()
            cur.execute(sql, (key_id,))
            return cur.fetchone()
        except Error as e:
            print(e)
            return None

    def get_key_pairs(self, user_id: int) -> List[Tuple[int, int, str, str, str, str]]:
        """获取用户的密钥对"""
        sql = """SELECT * FROM keys WHERE user_id = ?"""
        try:
            cur = self.conn.cursor()
            cur.execute(sql, (user_id,))
            return cur.fetchall()
        except Error as e:
            print(e)
            return []
    
    def add_signature(self, user_id: int, key_id: int, file_path: str, file_hash: str, signature: str) -> int:
        """添加签名"""
        sql = """INSERT INTO signatures(user_id, key_id, file_path, file_hash, signature) VALUES(?,?,?,?,?)"""
        try:
            cur = self.conn.cursor()
            cur.execute(sql, (user_id, key_id, file_path, file_hash, signature))
            self.conn.commit()
            return cur.lastrowid
        except Error as e:
            print(e)
            return -1
    
    def get_signature_by_user_file_algorithm(self, user_id: int, file_path: str, algorithm: str) -> Optional[Tuple[int, int, int, str, str, str, str]]:
        """根据用户ID、文件路径和算法获取签名"""
        sql = """SELECT s.* FROM signatures s 
                 JOIN keys k ON s.key_id = k.id 
                 WHERE s.user_id = ? AND s.file_path = ? AND k.algorithm = ?"""
        try:
            cur = self.conn.cursor()
            cur.execute(sql, (user_id, file_path, algorithm))
            return cur.fetchone()
        except Error as e:
            print(e)
            return None

    def get_signatures(self, user_id: int) -> List[Tuple[int, int, int, str, str, str, str]]:
        """获取用户的签名"""
        sql = """SELECT s.*, k.algorithm FROM signatures s 
                 JOIN keys k ON s.key_id = k.id 
                 WHERE s.user_id = ?"""
        try:
            cur = self.conn.cursor()
            cur.execute(sql, (user_id,))
            return cur.fetchall()
        except Error as e:
            print(e)
            return []
    
    def begin_transaction(self) -> None:
        """开始数据库事务"""
        self.conn.execute('BEGIN TRANSACTION;')

    def commit_transaction(self) -> None:
        """提交数据库事务"""
        self.conn.commit()

    def rollback_transaction(self) -> None:
        """回滚数据库事务"""
        self.conn.rollback()

    def delete_key_pair(self, key_id: int) -> bool:
        """删除指定ID的密钥记录"""
        sql = "DELETE FROM keys WHERE id = ?"
        try:
            cur = self.conn.cursor()
            cur.execute(sql, (key_id,))
            return cur.rowcount > 0
        except Error as e:
            print(e)
            return False

    def delete_signatures_by_key(self, key_id: int) -> bool:
        """删除指定密钥关联的签名记录"""
        sql = "DELETE FROM signatures WHERE key_id = ?"
        try:
            cur = self.conn.cursor()
            cur.execute(sql, (key_id,))
            return cur.rowcount > 0
        except Error as e:
            print(e)
            return False

    def get_signature_ids_by_key_id(self, key_id: int) -> List[int]:
        """根据密钥ID获取关联的签名ID列表"""
        sql = "SELECT id FROM signatures WHERE key_id = ?"
        try:
            cur = self.conn.cursor()
            cur.execute(sql, (key_id,))
            return [row[0] for row in cur.fetchall()]
        except Error as e:
            print(e)
            return []

    def close(self) -> None:
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()