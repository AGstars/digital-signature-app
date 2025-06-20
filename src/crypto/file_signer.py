import os
import hashlib
import base64
from gmssl import sm2, func, sm3  # 新增sm3导入
from cryptography.hazmat.backends import default_backend  # 补充导入
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from typing import Tuple

class FileSigner:
    def _preprocess_sm2_data(self, file_content: bytes) -> str:
        """SM2签名前的数据预处理：计算SM3哈希并转为十六进制字符串"""
        # 计算SM3哈希
        sm3_hash = sm3.sm3_hash(func.bytes_to_list(file_content))
        return sm3_hash  # 返回64字符的十六进制字符串
    
    def sign_file(self, private_key_pem: str, file_path: str, algorithm: str) -> Tuple[bytes, str]:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
        file_size = os.path.getsize(file_path)
        if file_size > 1 * 1024 * 1024:
            raise ValueError("文件大小超过1MB")
        with open(file_path, 'rb') as f:
            file_content = f.read()
        file_hash = self._calculate_file_hash(file_content)
        private_key = self._load_private_key(private_key_pem, algorithm)
        if algorithm.startswith("RSA"):
            if algorithm == "RSA-SHA1":
                hash_algorithm = hashes.SHA1()
            else:
                hash_algorithm = hashes.SHA256()
            signature = private_key.sign(
                file_content,
                padding.PSS(
                    mgf=padding.MGF1(hash_algorithm),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                algorithm=hash_algorithm
            )
        elif algorithm.startswith("ECDSA"):
            signature = private_key.sign(
                file_content,
                ec.ECDSA(hashes.SHA256())
            )
        elif algorithm.startswith('DSA'):
            signature = private_key.sign(
                file_content,
                hashes.SHA256()
            )
        elif algorithm == "SM2":
            # 使用SM2算法签名
            # 1. 数据预处理：计算SM3哈希并转为十六进制字符串
            sm2_data = self._preprocess_sm2_data(file_content)
            # 2. 生成64字节随机数K（十六进制字符串格式）
            K = func.random_hex(64)
            # 3. 执行签名
            signature_hex = private_key.sign(bytes.fromhex(sm2_data), K)
            # 4. 将十六进制签名转换为字节
            signature = bytes.fromhex(signature_hex)
        return signature, file_hash

    def _load_private_key(self, private_key_pem: str, algorithm: str):
        if algorithm == "SM2":
            # 1. 移除PEM头部、尾部和空白字符
            pem_content = private_key_pem.replace('-----BEGIN PRIVATE KEY-----', '').replace('-----END PRIVATE KEY-----', '').replace('\n', '').strip()
            # 2. Base64解码为字节数据
            private_key_bytes = base64.b64decode(pem_content)
            
            # 添加严格的私钥验证
            if len(private_key_bytes) != 32:
                raise ValueError(f"SM2私钥必须为32字节，实际为{len(private_key_bytes)}字节")
            
            # 3. 转换字节为十六进制字符串（64字符）
            private_key_hex = private_key_bytes.hex()
            if len(private_key_hex) != 64:
                raise ValueError(f"SM2私钥十六进制字符串必须为64字符，实际为{len(private_key_hex)}字符")
            
            # 4. 使用十六进制私钥初始化CryptSM2
            return sm2.CryptSM2(private_key=private_key_hex, public_key='')
        elif algorithm in ["RSA", "ECC"]:
            # 保留其他算法的通用加载方法
            return serialization.load_pem_private_key(
                private_key_bytes,
                password=None,
                backend=default_backend()
            )
        else:
            return serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )

    def _calculate_file_hash(self, file_content: bytes) -> str:
        hash_obj = hashlib.sha256()
        hash_obj.update(file_content)
        return hash_obj.hexdigest()