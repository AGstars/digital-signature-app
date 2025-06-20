import hashlib
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QPushButton, QMessageBox)

class LoginWindow(QWidget):
    """登录窗口"""
    def __init__(self, auth_manager, main_window):
        super().__init__()
        self.auth_manager = auth_manager
        self.main_window = main_window
        self.init_ui()
    
    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle('用户登录')
        self.setGeometry(300, 300, 300, 200)
        
        # 创建布局
        main_layout = QVBoxLayout()
        
        # 用户名
        username_layout = QHBoxLayout()
        username_label = QLabel('用户名:')
        self.username_input = QLineEdit()
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_input)
        
        # 密码
        password_layout = QHBoxLayout()
        password_label = QLabel('密码:')
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        
        # 按钮
        button_layout = QHBoxLayout()
        login_button = QPushButton('登录')
        login_button.clicked.connect(self.handle_login)
        register_button = QPushButton('注册')
        register_button.clicked.connect(self.handle_register)
        button_layout.addWidget(login_button)
        button_layout.addWidget(register_button)
        
        # 添加所有布局到主布局
        main_layout.addLayout(username_layout)
        main_layout.addLayout(password_layout)
        main_layout.addLayout(button_layout)
        
        self.setLayout(main_layout)
    
    def handle_login(self):
        """处理登录"""
        username = self.username_input.text()
        password = self.password_input.text()
        
        if not username or not password:
            QMessageBox.warning(self, '登录失败', '用户名和密码不能为空')
            return
        
        # 验证用户
        if self.auth_manager.login(username, password):
            QMessageBox.information(self, '登录成功', f'欢迎回来，{username}!')
            self.main_window.show_main_view()
            self.close()
        else:
            QMessageBox.warning(self, '登录失败', '用户名或密码错误')
    
    def handle_register(self):
        """处理注册"""
        username = self.username_input.text()
        password = self.password_input.text()
        
        if not username or not password:
            QMessageBox.warning(self, '注册失败', '用户名和密码不能为空')
            return
        
        # 创建用户
        if self.auth_manager.register(username, password):
            QMessageBox.information(self, '注册成功', '用户创建成功，请登录')
        else:
            QMessageBox.warning(self, '注册失败', '用户名已存在')    