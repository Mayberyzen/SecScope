from PyQt6.QtWidgets import QMainWindow, QWidget, QTabWidget, QVBoxLayout

from GUI.network_monitor_ui import NetworkMonitorTab 
from GUI.file_analyzer_ui import FileUrlAnalyzerTab
from GUI.system_health_ui import SystemHealthTab
from GUI.pentest_tools_ui import PentestToolsTab


class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SecOps")
        self.resize(1100, 700)
        self.graphicsEffect()
        central_widget = QWidget(self)
        layout = QVBoxLayout(central_widget)

        self.tab_widget = QTabWidget(central_widget)

        self.network_monitor_tab = NetworkMonitorTab()
        self.file_url_analyzer_tab = FileUrlAnalyzerTab()
        self.system_health_tab = SystemHealthTab()
        self.pentest_tools_tab = PentestToolsTab()

        self.tab_widget.addTab(self.network_monitor_tab, "Network Monitor")
        self.tab_widget.addTab(self.file_url_analyzer_tab, "File & URL Analyzer")
        self.tab_widget.addTab(self.system_health_tab, "System Health")
        self.tab_widget.addTab(self.pentest_tools_tab, "Pentest Tools")

        layout.addWidget(self.tab_widget)

        self.setCentralWidget(central_widget)
