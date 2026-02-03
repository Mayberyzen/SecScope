from PyQt6.QtCore import QThread, pyqtSignal, QObject
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QPushButton,
    QLabel,
    QFormLayout,
    QGroupBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QPlainTextEdit,
)

from modules import system_health


class HealthScanWorker(QObject):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def run(self):
        try:
            result = system_health.run_system_health_scan()
        except Exception as e:
            self.error.emit(str(e))
            return
        self.finished.emit(result)


class SystemHealthTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.thread = None
        self.worker = None
        self._build_ui()

    def _build_ui(self):
        main_layout = QVBoxLayout(self)

        # Top info group
        info_group = QGroupBox("System Security Overview")
        info_layout = QFormLayout()

        self.firewall_label = QLabel("Unknown")
        self.defender_label = QLabel("Unknown")
        self.smartscreen_label = QLabel("Unknown")
        self.public_ip_label = QLabel("Unknown")
        self.dns_label = QLabel("Unknown")
        self.gateway_label = QLabel("Unknown")
        self.score_label = QLabel("N/A")

        info_layout.addRow("Firewall:", self.firewall_label)
        info_layout.addRow("Defender / AV:", self.defender_label)
        info_layout.addRow("SmartScreen:", self.smartscreen_label)
        info_layout.addRow("Public IP:", self.public_ip_label)
        info_layout.addRow("DNS:", self.dns_label)
        info_layout.addRow("Gateway:", self.gateway_label)
        info_layout.addRow("Risk Score:", self.score_label)

        info_group.setLayout(info_layout)

        # Startup entries
        startup_group = QGroupBox("Startup Programs")
        self.startup_table = QTableWidget(0, 3)
        self.startup_table.setHorizontalHeaderLabels(["Name", "Location", "Enabled"])
        self.startup_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        startup_layout = QVBoxLayout()
        startup_layout.addWidget(self.startup_table)
        startup_group.setLayout(startup_layout)

        # Summary
        summary_group = QGroupBox("Findings Summary")
        summary_layout = QVBoxLayout()
        self.summary_box = QPlainTextEdit()
        self.summary_box.setReadOnly(True)
        summary_layout.addWidget(self.summary_box)
        summary_group.setLayout(summary_layout)

        # Scan button
        self.scan_button = QPushButton("Run System Health Scan")

        main_layout.addWidget(info_group)
        main_layout.addWidget(startup_group)
        main_layout.addWidget(summary_group)
        main_layout.addWidget(self.scan_button)

        self.scan_button.clicked.connect(self.run_scan)

    def run_scan(self):
        self.scan_button.setEnabled(False)
        self.summary_box.setPlainText("Running system health scan...")

        self.thread = QThread(self)
        self.worker = HealthScanWorker()
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self._scan_finished)
        self.worker.error.connect(self._scan_error)
        self.worker.finished.connect(self.thread.quit)
        self.worker.error.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def _scan_finished(self, result: dict):
        self.scan_button.setEnabled(True)

        self.firewall_label.setText(result.get("firewall_status", "Unknown"))
        self.defender_label.setText(result.get("defender_status", "Unknown"))
        self.smartscreen_label.setText(result.get("smartscreen_status", "Unknown"))
        self.public_ip_label.setText(result.get("public_ip", "Unknown"))
        self.dns_label.setText(", ".join(result.get("dns_servers", [])))
        self.gateway_label.setText(result.get("gateway", "Unknown"))

        score = result.get("risk_score", 0)
        self.score_label.setText(f"{score:.1f}/100")

        # Startup programs
        startups = result.get("startup_programs", [])
        self.startup_table.setRowCount(0)
        for s in startups:
            row = self.startup_table.rowCount()
            self.startup_table.insertRow(row)
            self.startup_table.setItem(row, 0, QTableWidgetItem(s.get("name", "")))
            self.startup_table.setItem(row, 1, QTableWidgetItem(s.get("location", "")))
            self.startup_table.setItem(row, 2, QTableWidgetItem(str(s.get("enabled", True))))

        # Summary text
        self.summary_box.setPlainText(result.get("summary", ""))

    def _scan_error(self, message: str):
        self.scan_button.setEnabled(True)
        self.summary_box.setPlainText(f"Error during scan: {message}")
