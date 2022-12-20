# -*- coding: utf-8 -*-
# @Time: 19:06
import socket


def get_my_lan_ip():
    hostname = socket.gethostname()
    hosts = socket.gethostbyname_ex(hostname)[-1]
    ip = hosts[-1]
    final_ip = ip

    return final_ip


if __name__ == '__main__':
    print(get_my_lan_ip())
    print(type(get_my_lan_ip()))
