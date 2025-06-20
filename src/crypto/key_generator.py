from gmssl.sm2 import CryptSM2
from gmssl import func
from cryptography.hazmat.backends import default_backend  # 补充导入
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.primitives import serialization

from typing import Tuple
import base64

class KeyGenerator:
    def __init__(self):
        self.supported_algorithms = {
            "RSA-2048": self._generate_rsa_keys,
            "RSA-SHA1": self._generate_rsa_keys,
            "ECDSA-P256": self._generate_ecdsa_keys,
            "ECDSA-P384": self._generate_ecdsa_p384_keys,
            "SM2": self._generate_sm2_keys,
            "DSA": self._generate_dsa_keys
        }

    def generate_key_pair(self, algorithm: str) -> Tuple[str, str]:
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"不支持的算法: {algorithm}")
        result = self.supported_algorithms[algorithm]()
        if algorithm == "SM2":
            return result
        private_key, public_key = result
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        return private_pem, public_pem

    def _generate_sm2_keys(self) -> Tuple[str, str]:
        try:
            # 生成随机私钥
            private_key = func.random_hex(64)  # 64字符16进制私钥
            # 使用私钥初始化CryptSM2实例
            sm2_crypt = CryptSM2(private_key=private_key, public_key='')
            # 使用_kg方法计算公钥
            public_key = sm2_crypt._kg(int(private_key, 16), sm2_crypt.ecc_table['g'])
            # 手动构建PEM格式
            # 私钥PEM
            private_key_bytes = bytes.fromhex(private_key)
            private_pem = f"""-----BEGIN PRIVATE KEY-----
{base64.b64encode(private_key_bytes).decode('utf-8')}
-----END PRIVATE KEY-----"""
            # 公钥PEM（SM2公钥通常以04开头，包含x和y坐标）
            public_key_bytes = bytes.fromhex('04' + public_key)  # 添加04前缀表示非压缩格式
            public_pem = f"""-----BEGIN PUBLIC KEY-----
{base64.b64encode(public_key_bytes).decode('utf-8')}
-----END PUBLIC KEY-----"""
            return private_pem, public_pem
        except Exception as e:
            raise RuntimeError(f"SM2密钥生成失败: {str(e)}") from e

    def _generate_rsa_keys(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()  # 此处使用default_backend
        )
        return private_key, private_key.public_key()

    def _generate_ecdsa_keys(self) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        private_key = ec.generate_private_key(
            ec.SECP256R1(),
            backend=default_backend()  # 此处使用default_backend
        )
        return private_key, private_key.public_key()

    def _generate_ecdsa_p384_keys(self) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        private_key = ec.generate_private_key(
            ec.SECP384R1(),
            backend=default_backend()  # 此处使用default_backend
        )
        return private_key, private_key.public_key()

    def _generate_dsa_keys(self) -> Tuple[dsa.DSAPrivateKey, dsa.DSAPublicKey]:
        # 生成DSA参数
        parameters = dsa.generate_parameters(
            key_size=2048,
            backend=default_backend()
        )
        # 使用参数生成私钥
        private_key = parameters.generate_private_key()
        return private_key, private_key.public_key()
