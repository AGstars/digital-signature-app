import base64
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from src.database.database_manager import DatabaseManager
from src.crypto.signature_manager import SignatureManager

class SignatureManagerController:
    """签名管理器"""
    def __init__(self, db_manager: DatabaseManager, crypto_manager: SignatureManager, auth_manager):  # 添加auth_manager参数
        self.db_manager = db_manager
        self.crypto_manager = crypto_manager
        self.auth_manager = auth_manager
        self.db_manager = db_manager
        self.crypto_manager = crypto_manager
    
    def generate_key_pair(self, algorithm: str):
        """转发生成密钥对请求到加密模块"""
        return self.crypto_manager.generate_key_pair(algorithm)

    def save_signature(self, user_id: int, key_id: int, file_path: str, file_hash: str, signature: str) -> int:
        """保存签名并返回签名ID"""
        try:
            # 获取密钥信息以确定算法
            key = self.db_manager.get_key_pair_by_id(key_id)
            if not key:
                return -1  # 密钥不存在
            
            algorithm = key[2]  # 从密钥元组中获取算法
            
            # 检查是否已存在相同文件和算法的签名
            existing_sig = self.db_manager.get_signature_by_user_file_algorithm(user_id, file_path, algorithm)
            if existing_sig:
                return -2  # 已存在相同文件和算法的签名
            
            sig_id = self.db_manager.add_signature(user_id, key_id, file_path, file_hash, signature)
            return sig_id  # 直接返回数据库生成的签名ID（成功时>0，失败时<=0）
        except Exception as e:
            return -1
    
    def get_signatures(self, user_id: int):
        """获取用户的所有签名"""
        return self.db_manager.get_signatures(user_id)
    
    def get_signature(self, sig_id: int):
        """获取单个签名"""
        # 从数据库获取当前用户的所有签名（需要先获取当前用户ID）
        current_user_id = self.auth_manager.get_current_user_id()  # 从认证管理器获取当前用户ID
        signatures = self.db_manager.get_signatures(current_user_id)
        for sig in signatures:
            if sig[0] == sig_id:
                return sig
        return None
    
    def get_algorithm_for_signature(self, sig_id: int):
        """获取签名对应的算法"""
        signature = self.get_signature(sig_id)
        if signature:
            key_id = signature[2]
            # 获取当前用户的密钥（避免跨用户查询）
        current_user_id = self.auth_manager.get_current_user_id()
        keys = self.db_manager.get_key_pairs(current_user_id)
        for k in keys:
            if k[0] == key_id:
                return k[2]
        return None
    
    # 转发签名和验证方法到crypto_manager
    def sign_file(self, private_key_pem: str, file_path: str, algorithm: str):
        return self.crypto_manager.sign_file(private_key_pem, file_path, algorithm)
    
    def get_algorithm_from_public_key(self, public_key_pem: str) -> str:
        """从公钥PEM中识别算法类型"""
        try:
            # 尝试加载为SM2公钥
            from gmssl import sm2
            sm2_crypt = sm2.CryptSM2()
            sm2_crypt.load_public_key(public_key_pem)
            return 'SM2'
        except:
            pass
        
        public_key = self.crypto_manager._load_public_key(public_key_pem, 'dummy')  # 使用虚拟算法加载
        if isinstance(public_key, rsa.RSAPublicKey):
            return 'RSA-2048'  # 实际可扩展支持更多密钥长度
        elif isinstance(public_key, dsa.DSAPublicKey):
            return 'DSA'
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            curve_name = public_key.curve.name  # 获取椭圆曲线名称（如secp256r1对应P-256）
            if curve_name == 'secp256r1':
                return 'ECDSA-P256'
            elif curve_name == 'secp384r1':
                return 'ECDSA-P384'
            else:
                raise ValueError(f'不支持的椭圆曲线: {curve_name}')
        else:
            raise ValueError('无法识别的公钥类型')

    def get_sig_ids_by_key_id(self, key_id: int) -> list:
        """根据密钥ID获取关联的签名ID列表"""
        return self.db_manager.get_signature_ids_by_key_id(key_id)

    def verify_signature(self, public_key_pem: str, file_path: str, signature: bytes, algorithm: str):
        return self.crypto_manager.verify_signature(public_key_pem, file_path, signature, algorithm)