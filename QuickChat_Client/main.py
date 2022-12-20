import sys

from PyQt5 import QtWidgets

from AudioChat.AudioClient import AudioClient

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = AudioClient()
    MainWindow.show()
    sys.exit(app.exec_())