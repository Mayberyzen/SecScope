import threading
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QComboBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QGroupBox,
    QPlainTextEdit,
    QLabel,
)

from modules import network_monitor


class ConnectionMonitorWorker(QObject):
    connections_updated = pyqtSignal(list)
    log_message = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, interval=3.0):
        super().__init__()
        self._running = False
        self.interval = interval

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    def run(self):
        import time

        self.log_message.emit("[*] Connection monitor started.")
        self._running = True
        while self._running:
            try:
                connections = network_monitor.get_active_connections()
                self.connections_updated.emit(connections)
            except Exception as e:
                self.log_message.emit(f"[!] Error in connection monitor: {e}")
            time.sleep(self.interval)
        self.log_message.emit("[*] Connection monitor stopped.")
        self.finished.emit()


class PacketSnifferWorker(QObject):
    packet_captured = pyqtSignal(dict)
    log_message = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, interface: str):
        super().__init__()
        self.interface = interface
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        self.log_message.emit(f"[*] Packet sniffer started on interface: {self.interface}")
        try:
            sniffer = network_monitor.PacketSniffer(self.interface)
            sniffer.start_sniffing(self._handle_packet, self._stop_event)
        except PermissionError:
            self.log_message.emit("[!] Permission denied for sniffing. Run as admin/root.")
        except Exception as e:
            self.log_message.emit(f"[!] Packet sniffer error: {e}")
        self.log_message.emit("[*] Packet sniffer stopped.")
        self.finished.emit()

    def _handle_packet(self, packet_info: dict):
        self.packet_captured.emit(packet_info)


class NetworkMonitorTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.conn_thread = None
        self.conn_worker = None
        self.sniff_thread = None
        self.sniff_worker = None

        self._build_ui()
        self._populate_interfaces()

    def _build_ui(self):
        main_layout = QVBoxLayout(self)

        # Controls row
        controls_layout = QHBoxLayout()
        self.interface_dropdown = QComboBox()
        self.interface_dropdown.setPlaceholderText("Select interface")
        self.start_button = QPushButton("Start Monitoring")
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)

        controls_layout.addWidget(QLabel("Interface:"))
        controls_layout.addWidget(self.interface_dropdown)
        controls_layout.addStretch()
        controls_layout.addWidget(self.start_button)
        controls_layout.addWidget(self.stop_button)

        main_layout.addLayout(controls_layout)

        # Connections table
        connections_group = QGroupBox("Active Connections")
        connections_layout = QVBoxLayout()
        self.connections_table = QTableWidget(0, 6)
        self.connections_table.setHorizontalHeaderLabels(
            ["Local Address", "Remote Address", "Status", "PID", "Process", "Risk"]
        )
        self.connections_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        connections_layout.addWidget(self.connections_table)
        connections_group.setLayout(connections_layout)

        # Packet table
        packets_group = QGroupBox("Captured Packets")
        packets_layout = QVBoxLayout()
        self.packets_table = QTableWidget(0, 7)
        self.packets_table.setHorizontalHeaderLabels(
            ["Time", "Src", "Dst", "Proto", "Sport", "Dport", "Risk"]
        )
        self.packets_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        packets_layout.addWidget(self.packets_table)
        packets_group.setLayout(packets_layout)

        # Log panel
        log_group = QGroupBox("Log")
        log_layout = QVBoxLayout()
        self.log_panel = QPlainTextEdit()
        self.log_panel.setReadOnly(True)
        log_layout.addWidget(self.log_panel)
        log_group.setLayout(log_layout)

        main_layout.addWidget(connections_group, stretch=2)
        main_layout.addWidget(packets_group, stretch=2)
        main_layout.addWidget(log_group, stretch=1)

        self.start_button.clicked.connect(self.start_monitoring)
        self.stop_button.clicked.connect(self.stop_monitoring)

    def _populate_interfaces(self):
        try:
            interfaces = network_monitor.list_interfaces()
        except Exception as e:
            interfaces = []
            self._log(f"[!] Failed to list interfaces: {e}")
        self.interface_dropdown.clear()
        self.interface_dropdown.addItems(interfaces)

    def _log(self, message: str):
        self.log_panel.appendPlainText(message)

    def start_monitoring(self):
        iface = self.interface_dropdown.currentText().strip()
        if not iface:
            self._log("[!] Select an interface first.")
            return

        # Avoid double-start
        self.stop_monitoring()

        self.conn_thread = QThread(self)
        self.conn_worker = ConnectionMonitorWorker(interval=3.0)
        self.conn_worker.moveToThread(self.conn_thread)

        self.conn_thread.started.connect(self.conn_worker.run)
        self.conn_worker.connections_updated.connect(self.update_connections_table)
        self.conn_worker.log_message.connect(self._log)
        self.conn_worker.finished.connect(self.conn_thread.quit)
        self.conn_worker.finished.connect(self.conn_worker.deleteLater)
        self.conn_thread.finished.connect(self.conn_thread.deleteLater)

        # Packet sniffer thread
        self.sniff_thread = QThread(self)
        self.sniff_worker = PacketSnifferWorker(interface=iface)
        self.sniff_worker.moveToThread(self.sniff_thread)

        self.sniff_thread.started.connect(self.sniff_worker.run)
        self.sniff_worker.packet_captured.connect(self.add_packet_row)
        self.sniff_worker.log_message.connect(self._log)
        self.sniff_worker.finished.connect(self.sniff_thread.quit)
        self.sniff_worker.finished.connect(self.sniff_worker.deleteLater)
        self.sniff_thread.finished.connect(self.sniff_thread.deleteLater)

        self.conn_thread.start()
        self.sniff_thread.start()

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self._log(f"[*] Monitoring started on {iface}")

    def stop_monitoring(self):
        if self.conn_worker is not None:
            self.conn_worker.stop()
        if self.conn_thread is not None and self.conn_thread.isRunning():
            self.conn_thread.quit()
            self.conn_thread.wait()
        self.conn_worker = None
        self.conn_thread = None

        if self.sniff_worker is not None:
            self.sniff_worker.stop()
        if self.sniff_thread is not None and self.sniff_thread.isRunning():
            self.sniff_thread.quit()
            self.sniff_thread.wait()
        self.sniff_worker = None
        self.sniff_thread = None

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def update_connections_table(self, connections: list):
        self.connections_table.setRowCount(0)
        for conn in connections:
            row = self.connections_table.rowCount()
            self.connections_table.insertRow(row)

            self.connections_table.setItem(row, 0, QTableWidgetItem(conn.get("laddr", "")))
            self.connections_table.setItem(row, 1, QTableWidgetItem(conn.get("raddr", "")))
            self.connections_table.setItem(row, 2, QTableWidgetItem(conn.get("status", "")))
            self.connections_table.setItem(row, 3, QTableWidgetItem(str(conn.get("pid", ""))))
            self.connections_table.setItem(row, 4, QTableWidgetItem(conn.get("process", "")))

            risk = conn.get("risk_score", 0)
            risk_item = QTableWidgetItem(f"{risk:.1f}")
            if risk >= 70:
                risk_item.setForeground(Qt.GlobalColor.red)
            elif risk >= 40:
                risk_item.setForeground(Qt.GlobalColor.darkYellow)
            else:
                risk_item.setForeground(Qt.GlobalColor.darkGreen)
            self.connections_table.setItem(row, 5, risk_item)

    def add_packet_row(self, packet: dict):
        row = self.packets_table.rowCount()
        self.packets_table.insertRow(row)

        self.packets_table.setItem(row, 0, QTableWidgetItem(packet.get("time", "")))
        self.packets_table.setItem(row, 1, QTableWidgetItem(packet.get("src", "")))
        self.packets_table.setItem(row, 2, QTableWidgetItem(packet.get("dst", "")))
        self.packets_table.setItem(row, 3, QTableWidgetItem(packet.get("proto", "")))
        self.packets_table.setItem(row, 4, QTableWidgetItem(str(packet.get("sport", ""))))
        self.packets_table.setItem(row, 5, QTableWidgetItem(str(packet.get("dport", ""))))

        risk = packet.get("risk_score", 0)
        risk_item = QTableWidgetItem(f"{risk:.1f}")
        if risk >= 70:
            risk_item.setForeground(Qt.GlobalColor.red)
        elif risk >= 40:
            risk_item.setForeground(Qt.GlobalColor.darkYellow)
        else:
            risk_item.setForeground(Qt.GlobalColor.darkGreen)
        self.packets_table.setItem(row, 6, risk_item)

        self.packets_table.scrollToBottom()

    def closeEvent(self, event):
        self.stop_monitoring()
        super().closeEvent(event)
