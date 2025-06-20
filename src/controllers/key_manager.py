from src.database.database_manager import DatabaseManager
from typing import Tuple
from src.crypto.signature_manager import SignatureManager

class KeyManager:
    """密钥管理器"""
    def __init__(self, db_manager: DatabaseManager, signature_manager: SignatureManager):
        self.db_manager = db_manager
        self.signature_manager = signature_manager
    
    def generate_and_save_key(self, user_id: int, algorithm: str) -> Tuple[bool, str, int]:
        """生成并保存密钥对"""
        try:
            # 检查用户是否已存在该算法的密钥对
            existing_key = self.db_manager.get_key_pair_by_algorithm(user_id, algorithm)
            if existing_key:
                return False, f"用户已存在{algorithm}算法的密钥对", -1
            
            private_key, public_key = self.signature_manager.generate_key_pair(algorithm)
            key_id = self.db_manager.add_key_pair(user_id, algorithm, private_key, public_key)
            
            if key_id > 0:
                return True, f"密钥对生成成功 (ID: {key_id})", key_id
            else:
                return False, "保存密钥对失败", -1
        except Exception as e:
            return False, f"生成密钥对失败: {str(e)}", -1
    
    def get_keys(self, user_id: int):
        """获取用户的所有密钥"""
        return self.db_manager.get_key_pairs(user_id)
    
    def get_key(self, user_id: int, key_id: int):
        """获取当前用户的单个密钥"""
        keys = self.db_manager.get_key_pairs(user_id)  # 获取当前用户的密钥
        for key in keys:
            if key[0] == key_id:
                return key
        return None

    def delete_key(self, user_id: int, key_id: int) -> Tuple[bool, str]:
        """删除密钥及其关联数据"""
        try:
            # 获取密钥信息
            key = self.get_key(user_id, key_id)
            if not key:
                return False, "密钥不存在"

            # 开始数据库事务
            self.db_manager.begin_transaction()

            # 删除数据库中的密钥记录
            self.db_manager.delete_key_pair(key_id)

            # 删除关联的签名记录
            self.db_manager.delete_signatures_by_key(key_id)

            # 提交事务
            self.db_manager.commit_transaction()

            # 删除本地PEM文件
            pem_path = f"src/database/PEM/{key_id}.pem"
            try:
                import os
                if os.path.exists(pem_path):
                    os.remove(pem_path)
            except Exception as e:
                return False, f"删除PEM文件失败: {str(e)}"

            # 删除关联的签名文件
            sig_dir = "src/database/SignBase64"
            try:
                import os
                for filename in os.listdir(sig_dir):
                    if filename.startswith(f"sig_{key_id}_"):
                        os.remove(os.path.join(sig_dir, filename))
            except Exception as e:
                return False, f"删除签名文件失败: {str(e)}"

            return True, "密钥删除成功"
        except Exception as e:
            self.db_manager.rollback_transaction()
            return False, f"删除密钥失败: {str(e)}"
