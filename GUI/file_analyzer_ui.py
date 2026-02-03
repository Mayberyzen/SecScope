from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QFileDialog,
    QLineEdit,
    QLabel,
    QFormLayout,
    QGroupBox,
    QPlainTextEdit,
    QMessageBox,
)
import os

from modules import file_analyzer


class FileUrlAnalyzerTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        main_layout = QVBoxLayout(self)

        # === FILE ANALYZER ===
        file_group = QGroupBox("File Analyzer")
        file_layout = QVBoxLayout()

        file_select_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("Select a file...")
        browse_button = QPushButton("Browse")

        file_select_layout.addWidget(self.file_path_edit)
        file_select_layout.addWidget(browse_button)

        hashes_layout = QFormLayout()
        self.md5_edit = QLineEdit()
        self.sha1_edit = QLineEdit()
        self.sha256_edit = QLineEdit()
        self.entropy_edit = QLineEdit()
        self.packing_edit = QLineEdit()

        for w in (self.md5_edit, self.sha1_edit, self.sha256_edit, self.entropy_edit, self.packing_edit):
            w.setReadOnly(True)

        hashes_layout.addRow("MD5:", self.md5_edit)
        hashes_layout.addRow("SHA1:", self.sha1_edit)
        hashes_layout.addRow("SHA256:", self.sha256_edit)
        hashes_layout.addRow("Entropy:", self.entropy_edit)
        hashes_layout.addRow("Packing:", self.packing_edit)

        # === FILE ENCRYPTION / DECRYPTION UI ===
        crypto_group = QGroupBox("File Encryption / Decryption")
        crypto_layout = QFormLayout()

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        encrypt_btn = QPushButton("Encrypt File")
        decrypt_btn = QPushButton("Decrypt File")

        crypto_layout.addRow("Password:", self.password_input)
        crypto_layout.addRow(encrypt_btn, decrypt_btn)

        crypto_group.setLayout(crypto_layout)

        file_layout.addLayout(file_select_layout)
        file_layout.addLayout(hashes_layout)
        file_layout.addWidget(crypto_group)
        file_group.setLayout(file_layout)

        # === URL ANALYZER ===
        url_group = QGroupBox("URL Analyzer")
        url_layout = QVBoxLayout()

        url_form = QFormLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        url_form.addRow("URL:", self.url_input)

        analyze_button = QPushButton("Analyze URL")
        self.url_result_box = QPlainTextEdit()
        self.url_result_box.setReadOnly(True)

        url_layout.addLayout(url_form)
        url_layout.addWidget(analyze_button)
        url_layout.addWidget(self.url_result_box)
        url_group.setLayout(url_layout)

        # Add groups to main layout
        main_layout.addWidget(file_group)
        main_layout.addWidget(url_group)

        # Connect buttons
        browse_button.clicked.connect(self._browse_file)
        analyze_button.clicked.connect(self._analyze_url)
        encrypt_btn.clicked.connect(self._encrypt_file)
        decrypt_btn.clicked.connect(self._decrypt_file)
        self.file_path_edit.editingFinished.connect(self._analyze_file_path)

    # === FILE HANDLING ===
    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file")
        if path:
            self.file_path_edit.setText(path)
            self._analyze_file_path()

    def _analyze_file_path(self):
        path = self.file_path_edit.text().strip()
        if not os.path.isfile(path):
            return

        try:
            hashes = file_analyzer.compute_hashes(path)
            entropy = file_analyzer.calculate_entropy(path)
            packing = file_analyzer.detect_packing(path)
        except Exception as e:
            self.packing_edit.setText(f"Error: {e}")
            return

        self.md5_edit.setText(hashes["md5"])
        self.sha1_edit.setText(hashes["sha1"])
        self.sha256_edit.setText(hashes["sha256"])
        self.entropy_edit.setText(f"{entropy:.3f}")
        self.packing_edit.setText(packing)

    # === ENCRYPTION / DECRYPTION ===
    def _encrypt_file(self):
        path = self.file_path_edit.text().strip()
        password = self.password_input.text().strip()

        if not path or not password:
            QMessageBox.warning(self, "Error", "Please select file and enter password")
            return

        try:
            out = file_analyzer.encrypt_file(path, password)
            QMessageBox.information(self, "Success", f"Encrypted:\n{out}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _decrypt_file(self):
        path = self.file_path_edit.text().strip()
        password = self.password_input.text().strip()

        if not path or not password:
            QMessageBox.warning(self, "Error", "Please select file and enter password")
            return

        try:
            out = file_analyzer.decrypt_file(path, password)
            QMessageBox.information(self, "Success", f"Decrypted:\n{out}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # === URL HANDLING ===
    def _analyze_url(self):
        url = self.url_input.text().strip()
        if not url:
            return

        result = file_analyzer.analyze_url(url)

        lines = [
            f"URL: {result['url']}",
            f"Domain: {result['domain']}",
            f"Scheme: {result['scheme']}",
            f"HTTPS: {result['is_https']}",
            "",
            f"Suspicious: {result['suspicious']}",
        ]

        if result["reasons"]:
            lines.append("\nReasons:")
            for r in result["reasons"]:
                lines.append(f"- {r}")

        self.url_result_box.setPlainText("\n".join(lines))
