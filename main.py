import sys
from PyQt6.QtWidgets import QApplication
from GUI.main_window_ui import MainWindow

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.setGeometry(100, 100, 1200, 800)
    window.showNormal()
    window.activateWindow()
    window.raise_()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
