# -*- coding: utf-8 -*-
# @Time: 21:10
from PyQt5.QtWidgets import QMainWindow, QFileDialog

from Utils.GetCurrentTime import get_time
from Utils.GetMyIP import get_my_lan_ip
from Utils.AESencode import encrypt, decrypt
from Utils.ECCmisc import get_key, ECC_encrypt, ECC_decrypt, ip_str2int
from UI.QuickChat import Ui_MainWindow

import socket
import threading
import pyaudio
import random
import string
import pathlib
import struct
import json
import time

import datetime


class AudioClient(QMainWindow, Ui_MainWindow):
    def __init__(self):
        # super(Client, self).__init__()
        super().__init__()
        self.setupUi(self)

        self.s_audio = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_text = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_file = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_cert = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_multi = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # SlotFunc
        # 语音传输
        self.btn_CTServer.clicked.connect(self.connect_to_server)
        self.btn_DTServer.clicked.connect(self.disconnect_to_server)
        self.btn_StartAudio.clicked.connect(self.start_audio)
        self.btn_CloseAudio.clicked.connect(self.close_audio)
        self.btn_Clear.clicked.connect(self.clear_info)

        # 建立连接：发送要聊天的ip
        self.btn_Connect.clicked.connect(self.build_connection)

        # 开始扫描，收到在线的ip
        self.btn_Scan.clicked.connect(self.start_to_scan)

        # 发送文字
        self.btn_SendText.clicked.connect(self.send_text)

        # 刷新聊天框
        self.btn_Refresh.clicked.connect(self.refresh_chat_box)

        # 发送文件
        self.btn_SendFile.clicked.connect(self.send_file_action)

        # 群聊
        self.btn_Refresh_2.clicked.connect(self.refresh_multi_chat_box)
        self.btn_MultiSendText.clicked.connect(self.send_multi_text)

        self.chunk_size = 1024  # 512
        self.audio_format = pyaudio.paInt16
        self.channels = 1
        self.rate = 20000
        self.target_ip = ""
        self.target_audio_port = 0
        self.target_control_port = 0
        self.target_text_port = 0
        self.target_file_port = 0
        self.target_cert_port = 0
        self.target_multi_port = 0

        self.AudioInfoText = ""
        self.is_send_audio = False
        self.is_receive_audio = False
        self.is_connected = False
        self.is_receive_text = False
        self.is_send_cert = False
        self.is_receive_file = False
        self.is_receive_multi_text = False

        self.connect_ip_data = ""
        self.scan_requirement = "Requirement for scanning all online sockets"
        self.offline_requirement = "Requirement for deleting my socket"

        self.p = pyaudio.PyAudio()
        self.playing_stream = 0
        self.recording_stream = 0

        self.textB_MyIP.setText(get_my_lan_ip())

        # 记录自己和接收到的文字
        self.ChatText = ""
        self.ChatText_pre = get_my_lan_ip() + "\n(" + socket.gethostname() + ")" + "："

        # 群聊
        self.MultiChatText = ""
        self.MultiChatText_pre = get_my_lan_ip() + "\n(" + socket.gethostname() + ")" + "："

        # 自己的私钥、收到的公钥
        self.myAESKEY = random.sample(string.ascii_letters, 16)
        self.myAESKEY = "".join(self.myAESKEY)
        self.youAESKEY = "1234567891111111"
        self.connections_keylist = {}
        self.myECCKEY = 0

    def receive_audio(self):
        while self.is_receive_audio:
            try:
                data = self.s_audio.recv(1024)
                print(type(data))
                self.playing_stream.write(data)
            except:
                pass
        print("The thread of receiver is killed")

    def send_audio(self):
        while self.is_send_audio:
            try:
                data = self.recording_stream.read(1024)
                self.s_audio.sendall(data)
            except:
                pass
        print("The thread of sender is killed")

    def connect_to_server(self):
        self.s_audio = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_text = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_file = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_cert = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_multi = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # print(self.textE_ServerIP.text())
        # while 1:
        try:
            self.target_ip = self.textE_ServerIP.text()
            self.target_audio_port = int(self.textE_AudioServerPort.text())
            self.s_audio.connect((self.target_ip, self.target_audio_port))

            # self.target_ip = self.textE_ServerIP.text()
            self.target_control_port = int(self.textE_ControlServerPort.text())
            self.s_control.connect((self.target_ip, self.target_control_port))

            # self.target_ip = self.textE_ServerIP.text()
            self.target_text_port = int(self.textE_TextServerPort.text())
            self.s_text.connect((self.target_ip, self.target_text_port))

            # self.target_ip = self.textE_ServerIP.text()
            self.target_file_port = int(self.textE_FileServerPort.text())
            self.s_file.connect((self.target_ip, self.target_file_port))

            self.target_cert_port = int(self.textE_CertServerPort.text())
            self.s_cert.connect((self.target_ip, self.target_cert_port))

            self.target_multi_port = int(self.textE_MultiChatPort.text())
            self.s_multi.connect((self.target_ip, self.target_multi_port))

            print("Connected to Server")
            self.AudioInfoText += "Connected to Server\n"
            self.textB_AudioInfo.setText(self.AudioInfoText)
            self.is_connected = True
            self.is_receive_audio = True
            self.is_receive_text = True
            self.is_send_cert = True
            self.is_receive_file = True
            self.is_receive_multi_text = True

            # 发送公钥，留私钥,key[0]为私钥key，key[1]、key[2]为公钥KEY_X KEY_Y
            ip = get_my_lan_ip()
            ip = ip_str2int(ip)
            self.myECCKEY = get_key(ip)
            print(self.myECCKEY)
            self.s_control.send(str(ip).encode() + " ".encode() + str(self.myECCKEY[1]).encode() + " ".encode() + str(
                self.myECCKEY[2]).encode())

            # 开始接听
            self.playing_stream = self.p.open(format=self.audio_format, channels=self.channels, rate=self.rate,
                                              output=True,
                                              frames_per_buffer=self.chunk_size)
            receive_audio_thread = threading.Thread(target=self.receive_audio).start()
            receive_text_thread = threading.Thread(target=self.receive_text).start()
            send_cert_thread = threading.Thread(target=self.send_cert).start()
            receive_file_thread = threading.Thread(target=self.receive_file).start()
            receive_multi_text_thread = threading.Thread(target=self.receive_multi_text).start()

            # test
            # display_text_chat_thread = threading.Thread(target=self.display_text_chat).start()

            print("正在接听...")
            self.AudioInfoText += "正在接听...\n"
            self.textB_AudioInfo.setText(self.AudioInfoText)


            # 接收ip
            # receive_ip_thread = threading.Thread(target=self.receive_server_ip).start()
            # break
        except:
            print("Couldn't connect to server")
            self.AudioInfoText += "Couldn't connect to server\n"
            self.textB_AudioInfo.setText(self.AudioInfoText)
            # break

    def muti_send_offline_requirement(self, msg):
        i = 10
        while i > 0:
            i -= 1
            self.s_control.send(msg)

    def disconnect_to_server(self):
        if self.is_connected:
            # 发送给服务器，服务器删掉自己的socket
            # self.s_control.send(self.offline_requirement.encode())
            self.muti_send_offline_requirement(self.offline_requirement.encode())

            self.s_audio.close()
            self.s_text.close()
            self.s_control.close()
            self.s_file.close()
            self.s_cert.close()
            self.s_multi.close()

            print("Disconnected to Server")
            self.AudioInfoText += "Disconnected to Server\n"
            self.textB_AudioInfo.setText(self.AudioInfoText)
            self.is_connected = False
            self.is_receive_audio = False
            self.is_send_audio = False
            self.is_receive_text = False
            self.is_send_cert = False
            self.is_receive_file = False
            self.is_receive_multi_text = False

            self.recording_stream = 0
            print("停止接听")
            self.AudioInfoText += "停止接听\n"
            self.textB_AudioInfo.setText(self.AudioInfoText)
        else:
            print("未连接服务器")
            self.AudioInfoText += "未连接服务器\n"
            self.textB_AudioInfo.setText(self.AudioInfoText)

    def start_audio(self):
        if self.is_connected:
            self.is_send_audio = True
            # 语音
            self.recording_stream = self.p.open(format=self.audio_format, channels=self.channels, rate=self.rate,
                                                input=True,
                                                frames_per_buffer=self.chunk_size)
            # print(self.p)
            # print(self.playing_stream)
            # print(self.recording_stream)
            # start threads
            send_audio_thread = threading.Thread(target=self.send_audio).start()

            print("正在语音通话...")
            self.AudioInfoText += "正在语音通话...\n"
            self.textB_AudioInfo.setText(self.AudioInfoText)
        else:
            print("未连接服务器")
            self.AudioInfoText += "未连接服务器\n"
            self.textB_AudioInfo.setText(self.AudioInfoText)

    def close_audio(self):
        if self.is_connected:
            self.is_send_audio = False
            # self.playing_stream = 0
            self.recording_stream = 0
            print("语音已关闭")
            self.AudioInfoText += "语音已关闭\n"
            self.textB_AudioInfo.setText(self.AudioInfoText)
            # receive_thread = threading.Thread(target=self.receive_server_data)._delete()
            # send_thread = threading.Thread(target=self.send_data_to_server)._delete()
        else:
            print("未连接服务器")
            self.AudioInfoText += "未连接服务器\n"
            self.textB_AudioInfo.setText(self.AudioInfoText)

    def clear_info(self):
        self.AudioInfoText = ""
        self.textB_AudioInfo.setText(self.AudioInfoText)

    # 建立连接
    def build_connection(self):
        if self.is_connected:
            self.connect_ip_data = ip_str2int(self.textE_InputIP.text())
            self.s_cert.send(str(self.connect_ip_data).encode())
        else:
            print("未连接服务器")
            self.AudioInfoText += "未连接服务器\n"
            self.textB_AudioInfo.setText(self.AudioInfoText)

    def send_cert(self):
        while self.is_send_cert:
            try:
                recv_KEY = self.s_cert.recv(1024)
                recv_KEY = recv_KEY.decode()
                # print(recv_KEY)
                KEY_list = recv_KEY.split(" ")
                # print(KEY_list)
                print("my keys", self.myAESKEY, int(KEY_list[0]), int(KEY_list[1]))
                cert = ECC_encrypt(self.myAESKEY, int(KEY_list[0]), int(KEY_list[1]));
                print("str" + str(cert))
                print(list(cert))

                self.s_cert.send(str(cert).encode())
                print("my cert send")

                input_cert = self.s_cert.recv(1024)
                print("your cert recv")

                input_cert = input_cert.decode()
                print("input_cert", type(input_cert), input_cert)

                input_cert = eval(input_cert)
                print("input_cert", type(input_cert), input_cert)

                self.youAESKEY = ECC_decrypt(self.myECCKEY[0], input_cert)
                print("youAESKEY", self.youAESKEY)

            except:
                print("??")

    # 控制信号：请求与Server绑定的ip
    # 开始扫描
    def start_to_scan(self):
        if self.is_connected:
            # self.control_info = "a"
            self.muti_send_offline_requirement(self.scan_requirement.encode())
            # self.s_control.send(self.scan_requirement.encode())
            self.receive_client_ip()
        else:
            print("未连接服务器")
            self.AudioInfoText += "未连接服务器\n"
            self.textB_AudioInfo.setText(self.AudioInfoText)

    def receive_client_ip(self):
        while True:
            try:
                recv_data = self.s_control.recv(1024)
                print(recv_data.decode())
                print(type(recv_data.decode()))
                self.textB_RecvIP.setText(recv_data.decode())
                print("!!!")
                break
            except:
                pass
        # print("The thread of receiver is killed")

    def send_text(self):
        if self.is_connected:
            current_time = get_time()
            send_text = "[" + current_time + "]" + self.ChatText_pre + self.textE_TextInput.toPlainText() + '\n'
            self.ChatText += send_text
            self.textE_TextInput.setPlainText("")
            self.textB_TextChat.setText(self.ChatText)
            send_text = encrypt(send_text, self.myAESKEY.encode('utf-8'))
            print(send_text)
            self.s_text.send(send_text)
        else:
            print("未连接服务器")
            self.AudioInfoText += "未连接服务器\n"
            self.textB_AudioInfo.setText(self.AudioInfoText)

    def receive_text(self):
        while self.is_receive_text:
            try:
                print("是否循环？")
                recv_text = self.s_text.recv(1024)
                print("1")
                print(recv_text.decode(), self.youAESKEY.encode('utf-8'))

                if self.youAESKEY == "1234567891111111":
                    print("加密的信息，无法解密")
                    self.ChatText += "加密的信息，无法解密" + '\n'
                    print(self.ChatText)
                    continue

                recv_text = decrypt(recv_text.decode(), self.youAESKEY.encode('utf-8'))
                print("2")
                # print(recv_text)
                self.ChatText += recv_text
                print("3")
                print(self.ChatText)
                # 这出问题了！！
                # 不能放到线程里
                # self.display_text_chat()
                # self.textB_TextChat.setText(self.ChatText)
                print("4")
            except:
                print("??")
            # finally:
            #     self.textB_TextChat.setText(self.ChatText)

    def send_multi_text(self):
        if self.is_connected:
            current_time = get_time()
            send_text = "[" + current_time + "]" + self.MultiChatText_pre + self.textE_MultiTextInput.toPlainText() + '\n'
            self.MultiChatText += send_text
            self.textE_MultiTextInput.setPlainText("")
            self.textB_MultiTextChat.setText(self.MultiChatText)
            print(send_text)
            self.s_multi.send(send_text.encode())
        else:
            print("未连接服务器")
            self.AudioInfoText += "未连接服务器\n"
            self.textB_AudioInfo.setText(self.AudioInfoText)

    def receive_multi_text(self):
        while self.is_receive_multi_text:
            try:
                # print("是否循环？")
                recv_text = self.s_multi.recv(1024)
                # print("1")
                # print(recv_text.decode(), self.youAESKEY.encode('utf-8'))
                recv_text = recv_text.decode()
                self.MultiChatText += recv_text
                print(self.MultiChatText)
                # 这出问题了！！
                # 不能放到线程里
                # self.display_text_chat()
                # self.textB_TextChat.setText(self.ChatText)
            except:
                print("??")
            # finally:
            #     self.textB_TextChat.setText(self.ChatText)

    def display_text_chat(self):
        self.textB_TextChat.setText(self.ChatText)

    def receive_file(self):
        while self.is_receive_file:
            try:
                four_head_bytes = self.s_file.recv(4)
                # 接收报头字典的固定字节

                len_head_dic_json_bytes = struct.unpack("i", four_head_bytes)[0]
                # 报头字典的字节数

                head_dic_json_bytes = self.s_file.recv(len_head_dic_json_bytes)
                # 接收报头字典字节

                head_dic = json.loads(head_dic_json_bytes.decode("utf-8"))
                # 报头字典

                # print('head_dic:')
                # print(head_dic)
                suffix = head_dic['suffix']

                recv_size = 0
                recv_data = b''
                while recv_size < head_dic['total_size']:
                    part_data = self.s_file.recv(1024)
                    recv_data += part_data
                    recv_size += len(part_data)
                    print(part_data)

                print('接收文件')
                file_path = self.testE_FilePath.text()
                path = str(file_path) + '\\' + time.strftime("%Y%m%d%H%M%S", time.localtime()) + suffix
                # path = r'C:\Users\0w0\Desktop\recv_test' + '\\' + time.strftime("%Y%m%d%H%M%S", time.localtime()) + suffix

                with open(path, 'wb') as f:
                    f.write(recv_data)
            except:
                print("??")

    def send_file_action(self):
        if self.is_connected:
            file_name = self.select_file()
            if file_name is None:
                return
            print(file_name)
            threading.Thread(target=self.send_file, args=(file_name,)).start()
            # self.send_file(file_name)
        else:
            print("未连接服务器")
            self.AudioInfoText += "未连接服务器\n"
            self.textB_AudioInfo.setText(self.AudioInfoText)

    def select_file(self):
        r = QFileDialog.getOpenFileName(self, "选择您想要传输的文件", "~/")
        return r[0]

    def read_content(self, path):
        f = open(path, 'rb')
        suffix = pathlib.Path(path).suffix
        return f.read(), suffix

    def send_file(self, file_path):
        # file_path = r'C:\Users\Yyd的YOGA 14s\Desktop\证件照.jpg'
        data, suffix = self.read_content(file_path)
        total_size = len(data)

        head_dic = {'suffix': suffix, 'total_size': total_size}
        # 报头字典

        head_dic_json_bytes = json.dumps(head_dic).encode("utf-8")
        # 报头字典str然后转字节

        len_head_dic_json_bytes = len(head_dic_json_bytes)
        # 报头字典str字节数
        print(len_head_dic_json_bytes)
        four_head_bytes = struct.pack("i", len_head_dic_json_bytes)
        # 制作报头字典字节int的固定字节数

        self.s_file.send(four_head_bytes)
        # 发送报头字典字节int的固定字节数

        self.s_file.send(head_dic_json_bytes)
        # 发送报头字典

        self.s_file.send(data)
        # print(data)
        # SendFileThread(file_path, self.s_file).start()

    def refresh_chat_box(self):
        self.textB_TextChat.setText(self.ChatText)

    def refresh_multi_chat_box(self):
        self.textB_MultiTextChat.setText(self.MultiChatText)

# if __name__ == '__main__':
#     client = Client()
