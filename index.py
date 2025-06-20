import sys
import sys
from PyQt6.QtWidgets import QApplication
from src.views.main_window import MainWindow
from src.views.login_window import LoginWindow
from src.controllers.auth_manager import AuthManager
from src.controllers.key_manager import KeyManager
from src.controllers.signature_manager import SignatureManagerController as SignatureManager
from src.database.database_manager import DatabaseManager
from src.crypto.signature_manager import SignatureManager as CryptoSignatureManager  # 导入加密模块的SignatureManager

if __name__ == "__main__":
    crypto_manager = CryptoSignatureManager()  # 实例化crypto_manager
    app = QApplication(sys.argv)
    db_manager = DatabaseManager('digital_signature.db')
    auth_manager = AuthManager(db_manager)
    signature_manager = SignatureManager(db_manager, crypto_manager, auth_manager)  # 传入auth_manager参数
    key_manager = KeyManager(db_manager, signature_manager)  # 现在signature_manager已定义，可以传递
    window = MainWindow(auth_manager, key_manager, signature_manager)
    login_window = LoginWindow(auth_manager, window)
    login_window.show()
    sys.exit(app.exec())