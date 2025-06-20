from PyQt6.QtWidgets import (QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QPushButton, QComboBox, 
                             QTextEdit, QFileDialog, QTableWidget, 
                             QTableWidgetItem, QMessageBox, QSplitter, QLineEdit, QDialog)
from PyQt6.QtCore import Qt
import base64

class MainWindow(QMainWindow):
    """主窗口"""
    def __init__(self, auth_manager, key_manager, signature_manager):
        super().__init__()
        self.auth_manager = auth_manager
        self.key_manager = key_manager
        self.signature_manager = signature_manager
        self.current_user_id = None
        self.pem_dir = os.path.join(os.path.dirname(__file__), '..', 'database', 'PEM')
        self.sig_dir = os.path.join(os.path.dirname(__file__), '..', 'database', 'SignBase64')
        os.makedirs(self.pem_dir, exist_ok=True)
        os.makedirs(self.sig_dir, exist_ok=True)
        self.init_ui()
    
    def refresh_keys(self, user_id):
        """刷新密钥相关状态（兼容主窗口标签切换调用）"""
        self.current_user_id = user_id

    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle('数字签名应用')
        self.setGeometry(300, 300, 900, 600)
        
        # 创建标签页
        self.tabs = QTabWidget()
        
        # 创建各个功能页面
        self.keys_tab = KeysTab(self.key_manager, self.auth_manager, self.signature_manager)
        self.sign_tab = SignTab(self.signature_manager, self.key_manager, self.auth_manager)
        self.verify_tab = VerifyTab(self.signature_manager, self.key_manager, self.auth_manager)
        
        # 添加标签页
        self.tabs.addTab(self.keys_tab, '密钥管理')
        self.tabs.addTab(self.verify_tab, '签名管理')
        self.file_verify_tab = FileVerifyTab(self.signature_manager, self.key_manager, self.auth_manager)
        self.tabs.addTab(self.file_verify_tab, '文件验证')
        self.tabs.addTab(self.sign_tab, '文件签名')
        
        self.setCentralWidget(self.tabs)
        self.tabs.currentChanged.connect(self.on_tab_changed)
    
    def on_tab_changed(self, index):
        if index == 0:
            self.keys_tab.refresh_keys(self.current_user_id)
        elif index == 1:
            self.sign_tab.refresh_keys(self.current_user_id)
        elif index == 2:
            self.verify_tab.refresh_signatures(self.current_user_id)
        elif index == 3:
            self.file_verify_tab.refresh_keys(self.current_user_id)

    def show_main_view(self):
        """显示主视图"""
        self.current_user_id = self.auth_manager.get_current_user_id()
        self.keys_tab.refresh_keys(self.current_user_id)
        self.sign_tab.refresh_keys(self.current_user_id)
        self.verify_tab.refresh_keys(self.current_user_id)
        self.verify_tab.refresh_signatures(self.current_user_id)
        self.show()

class KeysTab(QWidget):
    """密钥管理标签页"""
    def __init__(self, key_manager, auth_manager, signature_manager):
        super().__init__()
        self.key_manager = key_manager
        self.auth_manager = auth_manager
        self.signature_manager = signature_manager
        self.current_user_id = None
        # 初始化PEM文件保存路径（对应database/PEM目录）
        self.pem_dir = os.path.join(os.path.dirname(__file__), '..', 'database', 'PEM')
        # 初始化签名文件保存路径（对应database/SignBase64目录）
        self.sig_dir = os.path.join(os.path.dirname(__file__), '..', 'database', 'SignBase64')
        self.init_ui()
    
    def init_ui(self):
        """初始化UI"""
        layout = QVBoxLayout()
        
        # 密钥生成区域
        gen_layout = QHBoxLayout()
        gen_label = QLabel('生成新密钥对:')
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(['RSA-2048', 'RSA-SHA1', 'ECDSA-P256', 'ECDSA-P384', 'SM2', 'DSA'])
        gen_button = QPushButton('生成')
        gen_button.clicked.connect(self.generate_key)
        
        gen_layout.addWidget(gen_label)
        gen_layout.addWidget(self.algorithm_combo)
        gen_layout.addWidget(gen_button)
        
        # 密钥列表
        self.keys_table = QTableWidget()
        self.keys_table.setColumnCount(4)
        self.keys_table.setHorizontalHeaderLabels(['ID', '算法', '创建时间', '操作'])
        self.keys_table.setColumnWidth(0, 50)
        self.keys_table.setColumnWidth(1, 100)
        self.keys_table.setColumnWidth(2, 200)
        self.keys_table.setColumnWidth(3, 150)
        
        # 添加到主布局
        layout.addLayout(gen_layout)
        layout.addWidget(self.keys_table)
        
        self.setLayout(layout)
    
    def generate_key(self):
        """生成密钥对"""
        if not self.current_user_id:
            return
            
        algorithm = self.algorithm_combo.currentText()
        success, message, key_id = self.key_manager.generate_and_save_key(self.current_user_id, algorithm)
            
        if success:
            # 保存公钥PEM到本地文件
            key = self.key_manager.get_key(self.current_user_id, key_id)
            if key:
                public_key_pem = key[4]
                algorithm = key[2]
                pem_filename = f'{algorithm}_{key_id}_key.pem'
                pem_path = os.path.join(self.pem_dir, pem_filename)
                with open(pem_path, 'w') as f:
                    f.write(public_key_pem)
            QMessageBox.information(self, '成功', message)
            self.refresh_keys(self.current_user_id)
        else:
            QMessageBox.warning(self, '失败', message)
    
    def refresh_keys(self, user_id):
        """刷新密钥列表"""
        self.current_user_id = user_id
        self.keys_table.setRowCount(0)
        
        keys = self.key_manager.get_keys(user_id)
        for row, key in enumerate(keys):
            key_id = key[0]
            algorithm = key[2]
            created_at = key[5]
            
            self.keys_table.insertRow(row)
            self.keys_table.setItem(row, 0, QTableWidgetItem(str(key_id)))
            self.keys_table.setItem(row, 1, QTableWidgetItem(algorithm))
            self.keys_table.setItem(row, 2, QTableWidgetItem(str(created_at)))
            
            # 操作按钮布局
            btn_layout = QHBoxLayout()
            btn_layout.setContentsMargins(0,0,0,0)
            
            # 查看按钮
            view_button = QPushButton('查看')
            view_button.clicked.connect(lambda checked, r=row: self.view_key(r))
            btn_layout.addWidget(view_button)
            
            # 删除按钮
            delete_button = QPushButton('删除')
            delete_button.clicked.connect(lambda checked, r=row: self.delete_key(r))
            btn_layout.addWidget(delete_button)
            
            # 添加到单元格
            widget = QWidget()
            widget.setLayout(btn_layout)
            self.keys_table.setCellWidget(row, 3, widget)
            
    def view_key(self, row):
        """查看密钥详情"""
        key_id = int(self.keys_table.item(row, 0).text())
        key = self.key_manager.get_key(self.current_user_id, key_id)  # 传递当前用户ID和密钥ID
        if key:
            dialog = KeyViewDialog(self, key)
            dialog.exec()
    
    def delete_key(self, row):
        """删除密钥及相关数据"""
        key_id = int(self.keys_table.item(row, 0).text())
        reply = QMessageBox.question(self, '确认删除', f'确定要删除密钥ID {key_id}吗？这将删除所有关联的签名记录和文件！',
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        try:
            # 在删除数据库记录前获取密钥信息
            key = self.key_manager.get_key(self.current_user_id, key_id)
            if not key:
                QMessageBox.warning(self, '删除失败', '找不到该密钥信息')
                return
            
            algorithm = key[2]
            
            # 获取关联的签名文件信息
            sig_ids = self.signature_manager.get_sig_ids_by_key_id(key_id)
            sig_files_to_delete = []
            for sig_id in sig_ids:
                signature = self.signature_manager.get_signature(sig_id)
                if signature:
                    file_path = signature[3]
                    file_name = os.path.basename(file_path).rsplit('.', 1)[0]
                    sig_filename = f'{algorithm}_{key_id}_{file_name}_sig.sig'
                    sig_path = os.path.join(self.sig_dir, sig_filename)
                    sig_files_to_delete.append(sig_path)
            
            # 删除PEM文件
            pem_filename = f'{algorithm}_{key_id}_key.pem'
            pem_path = os.path.join(self.pem_dir, pem_filename)
            
            # 删除数据库记录（级联删除签名）
            success = self.key_manager.delete_key(self.current_user_id, key_id)
            if not success:
                QMessageBox.warning(self, '删除失败', '数据库记录删除失败')
                return
            
            # 删除PEM文件（在数据库记录删除后执行）
            if os.path.exists(pem_path):
                os.remove(pem_path)
            
            # 删除关联的sig文件
            for sig_path in sig_files_to_delete:
                if os.path.exists(sig_path):
                    os.remove(sig_path)
            
            QMessageBox.information(self, '成功', '密钥及相关数据删除完成')
            # 刷新密钥列表显示最新状态
            self.refresh_keys(self.current_user_id)
        except Exception as e:
            QMessageBox.critical(self, '错误', f'删除过程中发生异常: {str(e)}')
      
class SignTab(QWidget):
    """文件签名标签页"""
    def __init__(self, signature_manager, key_manager, auth_manager):
        super().__init__()
        self.signature_manager = signature_manager
        self.key_manager = key_manager
        self.auth_manager = auth_manager
        self.current_user_id = None
        # 初始化签名文件保存路径（对应database/SignBase64目录）
        self.sig_dir = os.path.join(os.path.dirname(__file__), '..', 'database', 'SignBase64')
        self.init_ui()
    
    def init_ui(self):
        """初始化UI"""
        layout = QVBoxLayout()
        
        # 文件选择区域
        file_layout = QHBoxLayout()
        file_label = QLabel('选择文件:')
        self.file_path_edit = QLineEdit()
        file_button = QPushButton('浏览...')
        file_button.clicked.connect(self.select_file)
        
        file_layout.addWidget(file_label)
        file_layout.addWidget(self.file_path_edit)
        file_layout.addWidget(file_button)
        
        # 密钥选择区域
        key_layout = QHBoxLayout()
        key_label = QLabel('选择密钥:')
        self.key_combo = QComboBox()
        
        key_layout.addWidget(key_label)
        key_layout.addWidget(self.key_combo)
        
        # 签名按钮
        sign_button = QPushButton('生成签名')
        sign_button.clicked.connect(self.sign_file)
        
        # 添加到主布局
        layout.addLayout(file_layout)
        layout.addLayout(key_layout)
        layout.addWidget(sign_button)
        
        self.setLayout(layout)
    
    def refresh_keys(self, user_id):
        """刷新密钥下拉菜单"""
        self.current_user_id = user_id
        self.key_combo.clear()
        
        keys = self.key_manager.get_keys(user_id)
        for key in keys:
            key_id = key[0]
            algorithm = key[2]
            self.key_combo.addItem(f"{algorithm} (ID: {key_id})", key_id)
    
    def select_file(self):
        """选择文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            self.file_path_edit.setText(file_path)
    
    def refresh_keys(self, user_id):
        """刷新密钥列表"""
        self.current_user_id = user_id
        self.key_combo.clear()
        
        keys = self.key_manager.get_keys(user_id)
        for key in keys:
            key_id = key[0]
            algorithm = key[2]
            self.key_combo.addItem(f"{algorithm} (ID: {key_id})", key_id)
    
    def sign_file(self):
        """对文件进行签名"""
        if not self.current_user_id:
            return
            
        file_path = self.file_path_edit.text()
        if not file_path or not file_path.strip():
            QMessageBox.warning(self, '错误', '请选择要签名的文件')
            return
        
        if self.key_combo.count() == 0:
            QMessageBox.warning(self, '错误', '没有可用的密钥，请先生成密钥对')
            return
        
        # 获取选中的密钥
        current_index = self.key_combo.currentIndex()
        key_id = self.key_combo.itemData(current_index)
        key = self.key_manager.get_key(self.current_user_id, key_id)
        
        if not key:
            QMessageBox.warning(self, '错误', '所选密钥不存在')
            return
        
        private_key_pem = key[3]
        algorithm = key[2]
        
        try:
            # 签名文件
            signature, file_hash = self.signature_manager.sign_file(private_key_pem, file_path, algorithm)
            
            # 保存签名
            signature_base64 = base64.b64encode(signature).decode('utf-8')
            sig_id = self.signature_manager.save_signature(
                self.current_user_id, key_id, file_path, file_hash, signature_base64
            )
            if sig_id > 0:
                # 保存签名到本地文件
                algorithm = key[2]
                file_name = os.path.basename(file_path).rsplit('.', 1)[0]
                sig_filename = f'{algorithm}_{key_id}_{file_name}_sig.sig'
                sig_path = os.path.join(self.sig_dir, sig_filename)
                with open(sig_path, 'w') as f:
                    f.write(signature_base64)
                success, message = True, f'签名保存成功 (ID: {sig_id})'
            elif sig_id == -2:
                success, message = False, '该文件已使用此算法签名过'
            else:
                success, message = False, '保存签名失败'
            
            if success:
                QMessageBox.information(self, '成功', '文件签名成功')
            else:
                QMessageBox.warning(self, '失败', message)
                
        except Exception as e:
            QMessageBox.critical(self, '错误', f'签名过程中发生错误: {str(e)}')

import os

class FileVerifyTab(QWidget):
    def refresh_keys(self, user_id):
        """刷新密钥相关状态（兼容主窗口标签切换调用）"""
        self.current_user_id = user_id
    """文件验证标签页"""
    def __init__(self, signature_manager, key_manager, auth_manager):
        super().__init__()
        self.signature_manager = signature_manager
        self.key_manager = key_manager
        self.auth_manager = auth_manager
        self.current_user_id = None
        # 初始化签名文件保存路径
        self.sig_dir = os.path.join(os.path.dirname(__file__), '..', 'database', 'SignBase64')
        self.pem_dir = os.path.join(os.path.dirname(__file__), '..', 'database', 'PEM')
        self.init_ui()

    def init_ui(self):
        """初始化UI"""
        layout = QVBoxLayout()

        # 文件选择区域
        file_layout = QHBoxLayout()
        file_label = QLabel('选择文件:')
        self.file_path_edit = QLineEdit()
        file_button = QPushButton('浏览...')
        file_button.clicked.connect(self.select_file)

        file_layout.addWidget(file_label)
        file_layout.addWidget(self.file_path_edit)
        file_layout.addWidget(file_button)

        # 签名输入区域
        sig_layout = QHBoxLayout()
        sig_label = QLabel('签名内容:')
        self.sig_text = QTextEdit()
        self.sig_text.setPlaceholderText('粘贴Base64编码的签名或点击浏览导入')
        sig_button = QPushButton('导入签名文件...')
        sig_button.clicked.connect(self.import_sig_file)

        sig_layout.addWidget(sig_label)
        sig_layout.addWidget(self.sig_text)
        sig_layout.addWidget(sig_button)

        # 公钥导入区域
        pubkey_layout = QHBoxLayout()
        pubkey_label = QLabel('公钥内容:')
        self.pubkey_text = QTextEdit()
        self.pubkey_text.setPlaceholderText('粘贴公钥PEM内容或点击浏览导入')
        self.pubkey_text.textChanged.connect(self.on_pubkey_changed)
        pubkey_button = QPushButton('导入公钥文件...')
        pubkey_button.clicked.connect(self.import_pubkey_file)

        pubkey_layout.addWidget(pubkey_label)
        pubkey_layout.addWidget(self.pubkey_text)
        pubkey_layout.addWidget(pubkey_button)

        layout.addLayout(sig_layout)

        # 验证按钮
        verify_button = QPushButton('验证文件')
        verify_button.clicked.connect(self.verify_file)

        # 添加到主布局
        layout.addLayout(file_layout)
        layout.addLayout(pubkey_layout)
        # 算法识别显示区域
        algorithm_layout = QHBoxLayout()
        self.algorithm_label = QLabel('识别算法: ')
        self.algorithm_value = QLabel('未识别')
        algorithm_layout.addWidget(self.algorithm_label)
        algorithm_layout.addWidget(self.algorithm_value)
        layout.addLayout(algorithm_layout)
        layout.addWidget(verify_button)

        self.setLayout(layout)

    def select_file(self):
        """选择文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            self.file_path_edit.setText(file_path)

    def import_pubkey_file(self):
        """导入公钥文件"""
        # 获取主窗口实例以访问sig_dir属性
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择公钥文件", self.pem_dir, "PEM文件 (*.pem);;所有文件 (*)"
        )
        if file_path:
            with open(file_path, 'r') as f:
                self.pubkey_text.setPlainText(f.read())

    def on_pubkey_changed(self):
        """公钥内容变化时更新算法识别结果"""
        pubkey_pem = self.pubkey_text.toPlainText()
        if pubkey_pem.strip():  # 公钥内容不为空时尝试识别算法
            try:
                algorithm = self.signature_manager.get_algorithm_from_public_key(pubkey_pem)
                self.algorithm_value.setText(algorithm)
            except Exception as e:
                self.algorithm_value.setText(f'识别失败: {str(e)}')
        else:
            self.algorithm_value.setText('未识别')

    def import_sig_file(self):
        """导入签名文件并读取内容"""
        # 获取主窗口实例以访问sig_dir属性
        file_path, _ = QFileDialog.getOpenFileName(
            self, '选择签名文件', self.sig_dir, '签名文件 (*.sig);;所有文件 (*.*)'
        )
        if file_path:
            with open(file_path, 'r') as f:
                self.sig_text.setPlainText(f.read())

    def verify_file(self):
        """执行文件验证逻辑"""
        # 获取文件路径
        file_path = self.file_path_edit.text()
        if not file_path:
            QMessageBox.warning(self, '错误', '请先选择要验证的文件')
            return

        # 获取公钥PEM
        pubkey_pem = self.pubkey_text.toPlainText()
        if not pubkey_pem.strip():
            QMessageBox.warning(self, '错误', '请输入或导入公钥PEM内容')
            return

        # 获取签名数据
        sig_text = self.sig_text.toPlainText()
        if not sig_text.strip():
            QMessageBox.warning(self, '错误', '请输入或导入签名内容')
            return

        try:
            signature_bytes = base64.b64decode(sig_text)
        except Exception:
            QMessageBox.warning(self, '错误', '无效的签名格式，请使用Base64编码')
            return

        # 获取识别的算法
        algorithm = self.algorithm_value.text()
        if algorithm.startswith('识别失败') or algorithm == '未识别':
            QMessageBox.warning(self, '错误', '无法识别公钥对应的算法，请检查公钥有效性')
            return

        # 执行验证
        try:
            is_valid = self.signature_manager.verify_signature(pubkey_pem, file_path, signature_bytes, algorithm)
            if is_valid:
                QMessageBox.information(self, '成功', '文件签名验证通过！')
            else:
                QMessageBox.warning(self, '失败', '文件签名验证不通过！')
        except Exception as e:
            QMessageBox.critical(self, '错误', f'验证过程中发生异常: {str(e)}')
        """验证文件"""
        file_path = self.file_path_edit.text()
        if not file_path or not file_path.strip():
            QMessageBox.warning(self, '错误', '请选择要验证的文件')
            return

        pubkey_pem = self.pubkey_text.toPlainText()
        if not pubkey_pem.strip():
            QMessageBox.warning(self, '错误', '请输入或导入公钥内容')
            return

        try:
            algorithm = self.signature_manager.get_algorithm_from_public_key(pubkey_pem)
        except ValueError as e:
            QMessageBox.warning(self, '错误', f'无法识别公钥算法: {str(e)}')
            return

        try:
            try:
                signature_bytes = base64.b64decode(self.sig_text.toPlainText())
            except Exception:
                QMessageBox.warning(self, '错误', '无效的签名格式，请使用Base64编码')
                return

            is_valid = self.signature_manager.verify_signature(
                pubkey_pem, file_path, signature_bytes, algorithm
            )
            if is_valid:
                QMessageBox.information(self, '验证结果', '文件签名有效')
            else:
                QMessageBox.warning(self, '验证结果', '文件签名无效')
        except Exception as e:
            QMessageBox.critical(self, '错误', f'验证过程中发生错误: {str(e)}')

class VerifyTab(QWidget):
    """签名验证标签页"""
    def __init__(self, signature_manager, key_manager, auth_manager):
        super().__init__()
        self.signature_manager = signature_manager
        self.key_manager = key_manager
        self.auth_manager = auth_manager
        self.current_user_id = None
        self.init_ui()
    
    def init_ui(self):
        """初始化UI"""
        layout = QVBoxLayout()
        
        # 签名列表
        self.signatures_table = QTableWidget()
        self.signatures_table.setColumnCount(6)
        self.signatures_table.setHorizontalHeaderLabels(['ID', '文件路径', '算法', '文件哈希', '创建时间', '操作'])
        self.signatures_table.setColumnWidth(0, 50)
        self.signatures_table.setColumnWidth(1, 250)
        self.signatures_table.setColumnWidth(2, 100)
        self.signatures_table.setColumnWidth(3, 200)
        self.signatures_table.setColumnWidth(4, 150)
        self.signatures_table.setColumnWidth(5, 100)
        
        # 验证按钮点击事件
        self.signatures_table.cellClicked.connect(self.on_signature_selected)
        
        # 添加到主布局
        layout.addWidget(self.signatures_table)
        
        self.setLayout(layout)
    
    def refresh_signatures(self, user_id):
        """刷新签名列表"""
        self.current_user_id = user_id
        self.signatures_table.setRowCount(0)
        
        signatures = self.signature_manager.get_signatures(user_id)
        for row, sig in enumerate(signatures):
            sig_id = sig[0]
            file_path = sig[3]
            file_hash = sig[4]
            created_at = sig[6]
            algorithm = sig[7]
            
            self.signatures_table.insertRow(row)
            self.signatures_table.setItem(row, 0, QTableWidgetItem(str(sig_id)))
            self.signatures_table.setItem(row, 1, QTableWidgetItem(file_path))
            self.signatures_table.setItem(row, 2, QTableWidgetItem(algorithm))
            self.signatures_table.setItem(row, 3, QTableWidgetItem(file_hash))
            self.signatures_table.setItem(row, 4, QTableWidgetItem(str(created_at)))
            
            # 验证按钮
            verify_button = QPushButton('验证')
            verify_button.clicked.connect(lambda checked, r=row: self.verify_signature(r))
            self.signatures_table.setCellWidget(row, 5, verify_button)
    
    def refresh_keys(self, user_id):
        """刷新密钥相关状态（空实现以兼容主窗口调用）"""
        self.current_user_id = user_id

    def verify_signature(self, row):
        """验证签名"""
        sig_id = int(self.signatures_table.item(row, 0).text())
        signature = self.signature_manager.get_signature(sig_id)
        
        if not signature:
            QMessageBox.warning(self, '错误', '所选签名不存在')
            return
        
        key_id = signature[2]
        file_path = signature[3]
        signature_base64 = signature[5]
        algorithm = self.signature_manager.get_algorithm_for_signature(sig_id)
        if not algorithm:
            QMessageBox.warning(self, '错误', '无法获取签名对应的算法')
            return
        
        # 获取公钥
        key = self.key_manager.get_key(self.current_user_id, key_id)
        if not key:
            QMessageBox.warning(self, '错误', '关联的密钥不存在')
            return
            
        public_key_pem = key[4]
        if not public_key_pem:
            QMessageBox.warning(self, '错误', '关联的密钥公钥信息缺失')
            return
        
        # 解码签名
        try:
            signature_bytes = base64.b64decode(signature_base64)
        except Exception:
            QMessageBox.warning(self, '错误', '无效的签名格式')
            return
        
        # 验证签名
        try:
            is_valid = self.signature_manager.verify_signature(
                public_key_pem, file_path, signature_bytes, algorithm
            )
            if is_valid:
                QMessageBox.information(self, '验证结果', '签名有效，文件未被篡改')
            else:
                QMessageBox.warning(self, '验证结果', '签名无效，文件可能已被篡改')
        except ValueError as e:
                    QMessageBox.warning(self, '错误', str(e))
                    return
        except FileNotFoundError:
                    QMessageBox.warning(self, '错误', '文件不存在，请确保文件路径未改变')
        except Exception as e:
                    QMessageBox.critical(self, '错误', f'验证过程中发生错误: {str(e)}')
    
    def on_signature_selected(self, row, column):
        """处理签名选择"""
        # 如果点击的是验证按钮所在列，则不执行任何操作
        if column == 5:
            return

class KeyViewDialog(QDialog):
    """密钥查看对话框"""
    def __init__(self, parent, key):
        super().__init__(parent)
        self.setWindowTitle('密钥详情')
        self.setGeometry(400, 400, 600, 400)
        
        layout = QVBoxLayout()
        
        key_id, user_id, algorithm, private_key, public_key, created_at = key
        
        # 密钥信息
        info_layout = QHBoxLayout()
        info_layout.addWidget(QLabel(f'ID: {key_id}'))
        info_layout.addWidget(QLabel(f'算法: {algorithm}'))
        info_layout.addWidget(QLabel(f'创建时间: {created_at}'))
        
        # 私钥显示
        private_label = QLabel('私钥:')
        self.private_text = QTextEdit()
        self.private_text.setPlainText(private_key)
        self.private_text.setReadOnly(True)
        
        # 公钥显示
        public_label = QLabel('公钥:')
        self.public_text = QTextEdit()
        self.public_text.setPlainText(public_key)
        self.public_text.setReadOnly(True)
        
        # 按钮
        close_button = QPushButton('关闭')
        close_button.clicked.connect(self.close)
        
        # 添加到主布局
        layout.addLayout(info_layout)
        layout.addWidget(private_label)
        layout.addWidget(self.private_text)
        layout.addWidget(public_label)
        layout.addWidget(self.public_text)
        layout.addWidget(close_button)
        
        self.setLayout(layout)