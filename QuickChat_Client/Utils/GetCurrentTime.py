# -*- coding: utf-8 -*-
# @Time: 23:57

import datetime

def get_time():
    now_time = datetime.datetime.now()
    now_time = str(now_time)
    return now_time

if __name__ == '__main__':
    print(get_time())
    print(type(get_time()))