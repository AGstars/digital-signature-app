import os
import base64
import binascii
from gmssl import sm2, sm3, func
from cryptography.hazmat.backends import default_backend  # 补充导入
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hmac

class SignatureVerifier:
    def _preprocess_sm2_data(self, file_content: bytes) -> str:
        """SM2签名前的数据预处理：计算SM3哈希并转为十六进制字符串"""
        # 计算SM3哈希
        sm3_hash = sm3.sm3_hash(func.bytes_to_list(file_content))
        return sm3_hash  # 返回64字符的十六进制字符串

    def verify_signature(self, public_key_pem: str, file_path: str, signature: bytes, algorithm: str) -> bool:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
        with open(file_path, 'rb') as f:
            file_content = f.read()
        public_key = self._load_public_key(public_key_pem, algorithm)
        if not algorithm:
            raise ValueError('算法信息缺失')
        try:
            if algorithm.startswith("RSA"):
                if algorithm == "RSA-SHA1":
                    hash_algorithm = hashes.SHA1()
                else:
                    hash_algorithm = hashes.SHA256()
                public_key.verify(
                    signature,
                    file_content,
                    padding.PSS(
                        mgf=padding.MGF1(hash_algorithm),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    algorithm=hash_algorithm
                )
            elif algorithm == "SM2":
                # 使用SM2算法验证签名
                sm2_data = self._preprocess_sm2_data(file_content)

                # 对文件内容进行SM3哈希预处理
                # 对文件内容进行SM3哈希预处理并转换为字节
                sm3_hash_hex = sm3.sm3_hash(func.bytes_to_list(file_content))
                sm3_hash_bytes = bytes.fromhex(sm3_hash_hex)
                # 直接使用已解码的签名字节数据
                # 确保十六进制字符串仅包含ASCII字符
                signature_hex = binascii.hexlify(signature).decode('ascii')
                # 过滤掉任何非十六进制字符
                signature_hex = ''.join([c for c in signature_hex if c in '0123456789abcdefABCDEF'])
                # 转换为小写以确保一致性
                public_key.verify(signature_hex, sm3_hash_bytes)
            elif algorithm == "DSA":
                public_key.verify(
                    signature,
                    file_content,
                    hashes.SHA256()
                )
            else:
                public_key.verify(
                    signature,
                    file_content,
                    ec.ECDSA(hashes.SHA256())
                )
            return True
        except InvalidSignature:
            return False

    def _load_public_key(self, public_key_pem: str, algorithm: str):
        public_key_bytes = public_key_pem.encode('utf-8')
        if algorithm == "SM2":
            # 移除PEM头部、尾部和空白字符
            pem_content = public_key_pem.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').replace('\n', '').strip()
            # Add padding if needed for Base64 decoding
            padding = '=' * ((4 - len(pem_content) % 4) % 4)
            pem_content += padding
            # Base64解码为字节数据
            public_key_bytes = base64.b64decode(pem_content)
            # 转换为十六进制字符串并去除04前缀
            public_key_hex = public_key_bytes.hex()[2:]
            # 使用公钥初始化CryptSM2
            return sm2.CryptSM2(private_key='', public_key=public_key_hex)
        elif algorithm.startswith("RSA"):
            return serialization.load_pem_public_key(
                public_key_bytes,
                backend=default_backend()  # 此处使用default_backend
            )
        else:
            return serialization.load_pem_public_key(
                public_key_bytes,
                backend=default_backend()  # 此处使用default_backend
            )
