# -*- coding: utf-8 -*-

import socket
import threading
import sys
import struct
import json


class Server:
    def __init__(self):
        self.ip = socket.gethostbyname_ex(socket.gethostname())[-1][-1]
        while True:
            try:
                self.port_audio = 9808
                self.s_audio = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.s_audio.bind((self.ip, self.port_audio))
                self.port_txt = 9809
                self.s_txt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.s_txt.bind((self.ip, self.port_txt))
                self.port_file = 9810
                self.s_file = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.s_file.bind((self.ip, self.port_file))
                self.port_control = 9811
                self.s_control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.s_control.bind((self.ip, self.port_control))
                self.port_cert = 9812
                self.s_cert = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.s_cert.bind((self.ip, self.port_cert))

                self.port_multi = 9813
                self.s_multi = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.s_multi.bind((self.ip, self.port_multi))

                break
            except:
                print("Couldn't bind to that port")

        self.connections_cert = []
        self.connections_audio = []
        self.connections_txt = []
        self.connections_file = []
        self.connections_control = []
        self.connections_multi = []


        self.connections_keylist = {}
        self.ip_cert = {}

        self.scan_requirement = "Requirement for scanning all online sockets"
        self.offline_requirement = "Requirement for deleting my socket"

        # self.accept_connections_audio()
        # self.accept_connections_txt()
        # self.accept_connections_file()

        threading.Thread(target=self.accept_connections_audio).start()
        threading.Thread(target=self.accept_connections_txt).start()
        threading.Thread(target=self.accept_connections_file).start()
        threading.Thread(target=self.accept_connections_control).start()
        threading.Thread(target=self.accept_connections_cert).start()
        threading.Thread(target=self.accept_connections_multi).start()



        # threading.Thread(target=self.accept_disconnection_control).start()
        # self.accept_disconnection_control()
        self.connect_dict = {}

    # def accept_disconnection_control(self):
    #     try:
    #         for c in self.connections_control:
    #             threading.Thread(target=self.listen_disconnection_control, args=(c,)).start()
    #
    #     except socket.error:
    #         # c.close()
    #         pass

    def listen_disconnection_control(self, c):
        while True:
            data = c.recv(1024)
            # 有时候会接收不到
            print(data.decode())
            # 一直在循环1
            print("1")
            if data.decode() == self.offline_requirement:
                print("2")
                client_index = self.connections_control.index(c)
                print(client_index)
                self.connections_control.pop(client_index)
                self.connections_txt.pop(client_index)
                self.connections_audio.pop(client_index)
                self.connections_file.pop(client_index)
                self.connections_cert.pop(client_index)
                self.connections_multi.pop(client_index)

                print(c)
                print(self.connections_control)

                break
                # self.s_control.recv()

    def accept_connections_multi(self):
        self.s_multi.listen(100)

        print('Running on IP: ' + self.ip)
        print('Running on port: ' + str(self.port_multi))

        while True:
            c, addr = self.s_multi.accept()

            self.connections_multi.append(c)

            threading.Thread(target=self.handle_client_multi, args=(c, addr,)).start()

    def accept_connections_cert(self):
        self.s_cert.listen(100)

        print('Running on IP: ' + self.ip)
        print('Running on port: ' + str(self.port_cert))

        while True:
            c, addr = self.s_cert.accept()

            self.connections_cert.append(c)

            threading.Thread(target=self.handle_client_cert, args=(c, addr,)).start()

    def accept_connections_audio(self):
        self.s_audio.listen(100)

        print('Running on IP: ' + self.ip)
        print('Running on port: ' + str(self.port_audio))

        while True:
            c, addr = self.s_audio.accept()

            self.connections_audio.append(c)

            threading.Thread(target=self.handle_client_audio, args=(c, addr,)).start()

    def accept_connections_txt(self):
        self.s_txt.listen(100)

        print('Running on IP: ' + self.ip)
        print('Running on port: ' + str(self.port_txt))

        while True:
            c, addr = self.s_txt.accept()
            print("连接到")
            print(c)

            self.connections_txt.append(c)

            threading.Thread(target=self.handle_client_txt, args=(c, addr,)).start()

    def accept_connections_file(self):
        self.s_file.listen(100)

        print('Running on IP: ' + self.ip)
        print('Running on port: ' + str(self.port_file))

        while True:
            c, addr = self.s_file.accept()

            self.connections_file.append(c)

            threading.Thread(target=self.handle_client_file, args=(c, addr,)).start()

    def accept_connections_control(self):
        self.s_control.listen(100)

        print('Running on IP: ' + self.ip)
        print('Running on port: ' + str(self.port_control))

        while True:
            # self.s_control.listen(100)
            c, addr = self.s_control.accept()

            # if c in self.connections_control:
            #     pass
            # else:
            self.connections_control.append(c)
            print("断开连接后，再连接？")
            threading.Thread(target=self.handle_client_control, args=(c, addr,)).start()
            threading.Thread(target=self.listen_disconnection_control, args=(c,)).start()
            print("???")

    def broadcast_audio(self, sock, data):
        '''
        data = ""
        for soc in self.connections_audio:
            peer = soc.getpeername()
            ip = peer[0]
            data = data + ip + " "

        print("control data")
        print(data)
        '''

        for client in self.connections_audio:
            if client != self.s_audio and client != sock:
                # print("client.getpeername()")
                # print(client.getpeername())
                try:
                    #print("是否发送txt？")
                    client.send(data)
                    #print("发送成功，接收失败")
                except:
                    pass
                    #print("未发送txt")

        # TODO 后续功能：与特定ip建立连接
        # sock_ip = sock.getpeername()[0]
        # print("sock_ip")
        # print(sock_ip)
        # print("self.connect_dict[sock_ip]")
        # print(self.connect_dict[sock_ip])
        # for client in self.connections_audio:
        #     client_ip = client.getpeername()[0]
        #     print("client_ip")
        #     print(client_ip)
        #     if client_ip in self.connect_dict[sock_ip]:
        #         print("client_ip in self.connect_dict[sock_ip]")
        #         try:
        #             client.send(data)
        #         except:
        #             pass

    def broadcast_txt(self, sock, data):

        for client in self.connections_txt:
            if client != self.s_txt and client != sock:
                # print("client.getpeername()")
                # print(client.getpeername())
                try:
                    print("是否发送txt？")
                    client.send(data)
                    print("发送成功，接收失败")
                except:
                    print("未发送txt")

    def broadcast_multi(self, sock, data):

        for client in self.connections_multi:
            if client != self.s_multi and client != sock:
                # print("client.getpeername()")
                # print(client.getpeername())
                try:
                    print("是否发送multi_txt？")
                    client.send(data)
                    print("发送成功，接收失败")
                except:
                    print("未发送txt")

    def broadcast_file(self, sock, data, four_head_bytes, head_dic_json_bytes):
        for client in self.connections_file:
            if client != self.s_file and client != sock:
                # print("client.getpeername()")
                # print(client.getpeername())
                try:

                    client.send(four_head_bytes)
                    # 发送报头字典字节int的固定字节数

                    client.send(head_dic_json_bytes)
                    # 发送报头字典

                    print(data)
                    client.send(data)
                except:
                    print(1111)

    # def broadcast_file(self, sock, data):
    #     for client in self.connections_file:
    #         if client != self.s_file and client != sock:
    #             # print("client.getpeername()")
    #             # print(client.getpeername())
    #             try:
    #                 client.send(data)
    #             except:
    #                 pass

    def broadcast_control(self, sock, data):
        # print("broadcast_control")
        data = data.decode()
        # print(data)
        # print(data == 'a')
        if data == self.scan_requirement:
            send_data = ""
            for soc in self.connections_control:
                peer = soc.getpeername()
                ip = peer[0]
                send_data = send_data + ip + " "
            # print("control data")
            # print(send_data)
            for client in self.connections_control:
                if client == sock:
                    # print("client.getpeername()")
                    # print(client.getpeername())
                    try:
                        client.send(send_data.encode())
                    except:
                        pass
        else:
            data_list = data.split()
            # print(data_list)
            ip = sock.getpeername()[0]
            self.connect_dict[ip] = data_list
            # print("self.connect_dict")
            # print(self.connect_dict)
            # print("self.connect_dict['ip']")
            # print(self.connect_dict[ip])

    def handle_client_cert(self, c, addr):
        while 1:
            try:
                data = c.recv(1024)
                data = data.decode()
                print(type(data),data)
                if data[0] != '[':
                    input_ip = data
                    print("目的ip",c.getpeername()[0],"input_ip",input_ip)
                    self.ip_cert[c.getpeername()[0]]=[input_ip,None]
                    print("ip_cert",self.ip_cert)
                    if input_ip in self.connections_keylist.keys():
                        c.send(self.connections_keylist[input_ip][0].encode() + " ".encode() +
                               self.connections_keylist[input_ip][1].encode())
                    else:
                        print("ip not onlion")

                elif data[0] == '[':
                    cert = data
                    print("cert",cert)
                    self.ip_cert[c.getpeername()[0]][1] = cert
                    for ip in self.ip_cert.keys():
                        if c.getpeername()[0] == ip:
                            self.ip_cert[ip][1] = cert
                            print("self.ip_cert[ip][1]",self.ip_cert[ip][1])
                            str_ip = socket.inet_ntoa(struct.pack('!I', int(self.ip_cert[ip][0])))
                            print("str_ip", str_ip)

                            for client in self.connections_cert:
                                print(type(client.getpeername()[0]), client.getpeername()[0])
                                if str_ip == client.getpeername()[0]:
                                    client.send(cert.encode())
                                    print("cert is send")
                                else:
                                    print("ip is ont online --> cert not send")
                        else:
                            print("cert not add")
                else:
                    print("don't know what's input")

                '''
                input_ip = c.recv(1024)
                input_ip = input_ip.decode()
                print(input_ip)
                if input_ip in self.connections_keylist.keys():
                    c.send(self.connections_keylist[input_ip][0].encode()+" ".encode()+self.connections_keylist[input_ip][1].encode())
                else:
                    print("ip not onlion")
                # self.broadcast_audio(c, data)
                str_ip = socket.inet_ntoa(struct.pack('!I', int(input_ip)))
                print(type(str_ip),str_ip)
                cert = c.recv(1024)
                cert = cert.decode()
                print(cert)
                for client in self.connections_cert:
                    print(type(client.getpeername()[0]),client.getpeername()[0])
                    if str_ip == client.getpeername()[0]:
                        client.send(cert.encode())
                        print("cert is send")
                    else:
                        print("ip is ont online --> cert not send")
                        '''
            except socket.error:
                c.close()

    def handle_client_audio(self, c, addr):
        while 1:
            try:
                data = c.recv(1024)
                # print(data)
                self.broadcast_audio(c, data)

            except socket.error:
                c.close()

    def handle_client_multi(self, c, addr):
        while 1:
            try:
                data = c.recv(1024)
                print("!!!")
                print(data)
                self.broadcast_multi(c, data)

            except socket.error:
                c.close()

    def handle_client_txt(self, c, addr):
        while 1:
            try:
                data = c.recv(1024)
                print(data)
                print(data.decode())
                print(sys.getsizeof(data))
                self.broadcast_txt(c, data)

            except socket.error:
                c.close()

    def handle_client_file(self, c, addr):
        while 1:
            try:
                four_head_bytes = c.recv(4)
                # 接收报头字典的固定字节

                len_head_dic_json_bytes = struct.unpack("i", four_head_bytes)[0]
                # 报头字典的字节数

                head_dic_json_bytes = c.recv(len_head_dic_json_bytes)
                # 接收报头字典字节

                head_dic = json.loads(head_dic_json_bytes.decode("utf-8"))
                # 报头字典

                recv_size = 0
                recv_data = b''
                print(head_dic)
                while recv_size < head_dic['total_size']:
                    part_data = c.recv(1024)
                    recv_data += part_data
                    recv_size += len(part_data)
                # print(recv_data)
                self.broadcast_file(c, recv_data, four_head_bytes, head_dic_json_bytes)

            except socket.error:
                print(socket.error)
                c.close()

    # def handle_client_file(self, c, addr):
    #     while 1:
    #         try:
    #             data = c.recv(1024)
    #             # print(data)
    #             self.broadcast_file(c, data)
    #
    #         except socket.error:
    #             # print(socket.error)
    #             c.close()

    def handle_client_control(self, c, addr):
        while 1:
            try:
                data = c.recv(1024)

                data = data.decode()
                KEY_list = data.split(" ")
                self.connections_keylist[KEY_list[0]]=(KEY_list[1], KEY_list[2])
                print(self.connections_keylist)

                self.broadcast_control(c, data.encode())

            except socket.error:
                c.close()


if __name__ == '__main__':
    server = Server()
