# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'QuickChat.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1388, 837)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.textE_TextInput = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.textE_TextInput.setGeometry(QtCore.QRect(500, 380, 411, 121))
        self.textE_TextInput.setObjectName("textE_TextInput")
        self.btn_Scan = QtWidgets.QPushButton(self.centralwidget)
        self.btn_Scan.setGeometry(QtCore.QRect(340, 510, 93, 28))
        self.btn_Scan.setObjectName("btn_Scan")
        self.label_TextChat = QtWidgets.QLabel(self.centralwidget)
        self.label_TextChat.setGeometry(QtCore.QRect(500, 20, 91, 16))
        self.label_TextChat.setObjectName("label_TextChat")
        self.label_InputIP = QtWidgets.QLabel(self.centralwidget)
        self.label_InputIP.setGeometry(QtCore.QRect(30, 550, 411, 16))
        self.label_InputIP.setObjectName("label_InputIP")
        self.label_RecvIP = QtWidgets.QLabel(self.centralwidget)
        self.label_RecvIP.setGeometry(QtCore.QRect(30, 350, 111, 16))
        self.label_RecvIP.setObjectName("label_RecvIP")
        self.textB_RecvIP = QtWidgets.QTextBrowser(self.centralwidget)
        self.textB_RecvIP.setGeometry(QtCore.QRect(30, 380, 411, 121))
        self.textB_RecvIP.setObjectName("textB_RecvIP")
        self.btn_SendFile = QtWidgets.QPushButton(self.centralwidget)
        self.btn_SendFile.setGeometry(QtCore.QRect(340, 750, 93, 28))
        self.btn_SendFile.setObjectName("btn_SendFile")
        self.textB_MyIP = QtWidgets.QTextBrowser(self.centralwidget)
        self.textB_MyIP.setGeometry(QtCore.QRect(30, 50, 411, 41))
        self.textB_MyIP.setObjectName("textB_MyIP")
        self.textB_TextChat = QtWidgets.QTextBrowser(self.centralwidget)
        self.textB_TextChat.setGeometry(QtCore.QRect(500, 50, 411, 281))
        self.textB_TextChat.setObjectName("textB_TextChat")
        self.label_MyIP = QtWidgets.QLabel(self.centralwidget)
        self.label_MyIP.setGeometry(QtCore.QRect(30, 20, 101, 21))
        self.label_MyIP.setObjectName("label_MyIP")
        self.label_TextInput = QtWidgets.QLabel(self.centralwidget)
        self.label_TextInput.setGeometry(QtCore.QRect(500, 350, 101, 16))
        self.label_TextInput.setObjectName("label_TextInput")
        self.btn_SendText = QtWidgets.QPushButton(self.centralwidget)
        self.btn_SendText.setGeometry(QtCore.QRect(810, 510, 93, 28))
        self.btn_SendText.setObjectName("btn_SendText")
        self.textB_AudioInfo = QtWidgets.QTextBrowser(self.centralwidget)
        self.textB_AudioInfo.setGeometry(QtCore.QRect(500, 580, 411, 161))
        self.textB_AudioInfo.setObjectName("textB_AudioInfo")
        self.label_AudioInfo = QtWidgets.QLabel(self.centralwidget)
        self.label_AudioInfo.setGeometry(QtCore.QRect(500, 550, 121, 16))
        self.label_AudioInfo.setObjectName("label_AudioInfo")
        self.btn_Clear = QtWidgets.QPushButton(self.centralwidget)
        self.btn_Clear.setGeometry(QtCore.QRect(570, 750, 93, 28))
        self.btn_Clear.setObjectName("btn_Clear")
        self.btn_Connect = QtWidgets.QPushButton(self.centralwidget)
        self.btn_Connect.setGeometry(QtCore.QRect(340, 630, 93, 28))
        self.btn_Connect.setObjectName("btn_Connect")
        self.btn_CTServer = QtWidgets.QPushButton(self.centralwidget)
        self.btn_CTServer.setGeometry(QtCore.QRect(340, 210, 93, 28))
        self.btn_CTServer.setObjectName("btn_CTServer")
        self.label_AudioServerPort = QtWidgets.QLabel(self.centralwidget)
        self.label_AudioServerPort.setGeometry(QtCore.QRect(40, 220, 111, 16))
        self.label_AudioServerPort.setObjectName("label_AudioServerPort")
        self.textE_ServerIP = QtWidgets.QLineEdit(self.centralwidget)
        self.textE_ServerIP.setGeometry(QtCore.QRect(30, 140, 411, 41))
        self.textE_ServerIP.setObjectName("textE_ServerIP")
        self.label_ServerIP = QtWidgets.QLabel(self.centralwidget)
        self.label_ServerIP.setGeometry(QtCore.QRect(30, 110, 261, 21))
        self.label_ServerIP.setObjectName("label_ServerIP")
        self.btn_DTServer = QtWidgets.QPushButton(self.centralwidget)
        self.btn_DTServer.setGeometry(QtCore.QRect(340, 290, 93, 28))
        self.btn_DTServer.setObjectName("btn_DTServer")
        self.textE_AudioServerPort = QtWidgets.QLineEdit(self.centralwidget)
        self.textE_AudioServerPort.setGeometry(QtCore.QRect(120, 220, 61, 21))
        self.textE_AudioServerPort.setObjectName("textE_AudioServerPort")
        self.btn_CloseAudio = QtWidgets.QPushButton(self.centralwidget)
        self.btn_CloseAudio.setGeometry(QtCore.QRect(810, 750, 93, 28))
        self.btn_CloseAudio.setObjectName("btn_CloseAudio")
        self.btn_StartAudio = QtWidgets.QPushButton(self.centralwidget)
        self.btn_StartAudio.setGeometry(QtCore.QRect(690, 750, 93, 28))
        self.btn_StartAudio.setObjectName("btn_StartAudio")
        self.textE_TextServerPort = QtWidgets.QLineEdit(self.centralwidget)
        self.textE_TextServerPort.setGeometry(QtCore.QRect(120, 250, 61, 21))
        self.textE_TextServerPort.setObjectName("textE_TextServerPort")
        self.label_TextServerPort = QtWidgets.QLabel(self.centralwidget)
        self.label_TextServerPort.setGeometry(QtCore.QRect(40, 250, 111, 16))
        self.label_TextServerPort.setObjectName("label_TextServerPort")
        self.label_FileServerPort = QtWidgets.QLabel(self.centralwidget)
        self.label_FileServerPort.setGeometry(QtCore.QRect(40, 280, 111, 16))
        self.label_FileServerPort.setObjectName("label_FileServerPort")
        self.textE_FileServerPort = QtWidgets.QLineEdit(self.centralwidget)
        self.textE_FileServerPort.setGeometry(QtCore.QRect(120, 280, 61, 21))
        self.textE_FileServerPort.setObjectName("textE_FileServerPort")
        self.line = QtWidgets.QFrame(self.centralwidget)
        self.line.setGeometry(QtCore.QRect(453, 0, 31, 861))
        self.line.setFrameShape(QtWidgets.QFrame.VLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.textE_ControlServerPort = QtWidgets.QLineEdit(self.centralwidget)
        self.textE_ControlServerPort.setGeometry(QtCore.QRect(270, 220, 61, 21))
        self.textE_ControlServerPort.setObjectName("textE_ControlServerPort")
        self.label_ControlServerPort = QtWidgets.QLabel(self.centralwidget)
        self.label_ControlServerPort.setGeometry(QtCore.QRect(190, 220, 111, 16))
        self.label_ControlServerPort.setObjectName("label_ControlServerPort")
        self.textE_InputIP = QtWidgets.QLineEdit(self.centralwidget)
        self.textE_InputIP.setGeometry(QtCore.QRect(30, 580, 411, 41))
        self.textE_InputIP.setObjectName("textE_InputIP")
        self.btn_Refresh = QtWidgets.QPushButton(self.centralwidget)
        self.btn_Refresh.setGeometry(QtCore.QRect(810, 10, 93, 28))
        self.btn_Refresh.setObjectName("btn_Refresh")
        self.label_cert = QtWidgets.QLabel(self.centralwidget)
        self.label_cert.setGeometry(QtCore.QRect(190, 250, 72, 15))
        self.label_cert.setObjectName("label_cert")
        self.textE_CertServerPort = QtWidgets.QLineEdit(self.centralwidget)
        self.textE_CertServerPort.setGeometry(QtCore.QRect(270, 250, 61, 21))
        self.textE_CertServerPort.setObjectName("textE_CertServerPort")
        self.label_InputFilePath = QtWidgets.QLabel(self.centralwidget)
        self.label_InputFilePath.setGeometry(QtCore.QRect(30, 670, 181, 16))
        self.label_InputFilePath.setObjectName("label_InputFilePath")
        self.testE_FilePath = QtWidgets.QLineEdit(self.centralwidget)
        self.testE_FilePath.setGeometry(QtCore.QRect(30, 700, 411, 41))
        self.testE_FilePath.setObjectName("testE_FilePath")
        self.btn_Refresh_2 = QtWidgets.QPushButton(self.centralwidget)
        self.btn_Refresh_2.setGeometry(QtCore.QRect(1250, 10, 93, 28))
        self.btn_Refresh_2.setObjectName("btn_Refresh_2")
        self.textE_MultiTextInput = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.textE_MultiTextInput.setGeometry(QtCore.QRect(940, 620, 411, 121))
        self.textE_MultiTextInput.setObjectName("textE_MultiTextInput")
        self.label_MultiTextInput = QtWidgets.QLabel(self.centralwidget)
        self.label_MultiTextInput.setGeometry(QtCore.QRect(950, 590, 101, 16))
        self.label_MultiTextInput.setObjectName("label_MultiTextInput")
        self.btn_MultiSendText = QtWidgets.QPushButton(self.centralwidget)
        self.btn_MultiSendText.setGeometry(QtCore.QRect(1260, 750, 93, 28))
        self.btn_MultiSendText.setObjectName("btn_MultiSendText")
        self.textB_MultiTextChat = QtWidgets.QTextBrowser(self.centralwidget)
        self.textB_MultiTextChat.setGeometry(QtCore.QRect(940, 50, 411, 531))
        self.textB_MultiTextChat.setObjectName("textB_MultiTextChat")
        self.label_MultiTextChat = QtWidgets.QLabel(self.centralwidget)
        self.label_MultiTextChat.setGeometry(QtCore.QRect(940, 20, 91, 16))
        self.label_MultiTextChat.setObjectName("label_MultiTextChat")
        self.textE_MultiChatPort = QtWidgets.QLineEdit(self.centralwidget)
        self.textE_MultiChatPort.setGeometry(QtCore.QRect(270, 280, 61, 21))
        self.textE_MultiChatPort.setObjectName("textE_MultiChatPort")
        self.label_MultiChat = QtWidgets.QLabel(self.centralwidget)
        self.label_MultiChat.setGeometry(QtCore.QRect(190, 280, 72, 15))
        self.label_MultiChat.setObjectName("label_MultiChat")
        self.line_2 = QtWidgets.QFrame(self.centralwidget)
        self.line_2.setGeometry(QtCore.QRect(910, -50, 31, 861))
        self.line_2.setFrameShape(QtWidgets.QFrame.VLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_2.setObjectName("line_2")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1388, 26))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.btn_Scan.setText(_translate("MainWindow", "开始扫描"))
        self.label_TextChat.setText(_translate("MainWindow", "文字聊天框："))
        self.label_InputIP.setText(_translate("MainWindow", "输入您想聊天的IP地址："))
        self.label_RecvIP.setText(_translate("MainWindow", "在线IP地址："))
        self.btn_SendFile.setText(_translate("MainWindow", "发送文件"))
        self.label_MyIP.setText(_translate("MainWindow", "我的IP地址："))
        self.label_TextInput.setText(_translate("MainWindow", "文字输入框："))
        self.btn_SendText.setText(_translate("MainWindow", "发送文字"))
        self.label_AudioInfo.setText(_translate("MainWindow", "语音聊天状态："))
        self.btn_Clear.setText(_translate("MainWindow", "清空信息"))
        self.btn_Connect.setText(_translate("MainWindow", "建立连接"))
        self.btn_CTServer.setText(_translate("MainWindow", "连接服务器"))
        self.label_AudioServerPort.setText(_translate("MainWindow", "语音端口："))
        self.label_ServerIP.setText(_translate("MainWindow", "输入服务器IP地址："))
        self.btn_DTServer.setText(_translate("MainWindow", "断开连接"))
        self.textE_AudioServerPort.setText(_translate("MainWindow", "9808"))
        self.btn_CloseAudio.setText(_translate("MainWindow", "关闭语音"))
        self.btn_StartAudio.setText(_translate("MainWindow", "开始语音"))
        self.textE_TextServerPort.setText(_translate("MainWindow", "9809"))
        self.label_TextServerPort.setText(_translate("MainWindow", "文字端口："))
        self.label_FileServerPort.setText(_translate("MainWindow", "文件端口："))
        self.textE_FileServerPort.setText(_translate("MainWindow", "9810"))
        self.textE_ControlServerPort.setText(_translate("MainWindow", "9811"))
        self.label_ControlServerPort.setText(_translate("MainWindow", "控制端口："))
        self.btn_Refresh.setText(_translate("MainWindow", "刷新"))
        self.label_cert.setText(_translate("MainWindow", "认证端口："))
        self.textE_CertServerPort.setText(_translate("MainWindow", "9812"))
        self.label_InputFilePath.setText(_translate("MainWindow", "选择您想接收文件的路径："))
        self.btn_Refresh_2.setText(_translate("MainWindow", "刷新"))
        self.label_MultiTextInput.setText(_translate("MainWindow", "文字输入框："))
        self.btn_MultiSendText.setText(_translate("MainWindow", "发送文字"))
        self.label_MultiTextChat.setText(_translate("MainWindow", "多人聊天框："))
        self.textE_MultiChatPort.setText(_translate("MainWindow", "9813"))
        self.label_MultiChat.setText(_translate("MainWindow", "群聊端口："))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())