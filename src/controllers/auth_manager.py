import hashlib
from src.database.database_manager import DatabaseManager

class AuthManager:
    """认证管理器"""
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.current_user = None
    
    def register(self, username: str, password: str) -> bool:
        """注册新用户"""
        password_hash = self._hash_password(password)
        return self.db_manager.add_user(username, password_hash)
    
    def login(self, username: str, password: str) -> bool:
        """用户登录"""
        user = self.db_manager.get_user(username)
        if user:
            stored_hash = user[2]
            input_hash = self._hash_password(password)
            
            if stored_hash == input_hash:
                self.current_user = user
                return True
        
        return False
    
    def logout(self) -> None:
        """用户登出"""
        self.current_user = None
    
    def get_current_user_id(self) -> int:
        """获取当前用户ID"""
        if self.current_user:
            return self.current_user[0]
        return -1
    
    def _hash_password(self, password: str) -> str:
        """哈希密码"""
        salt = b'some_salt_here'  # 在实际应用中应该使用随机盐
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000).hex()    