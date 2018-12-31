# -*- coding: utf-8 -*-
"""
Created on Wed Dec 12 11:44:12 2018

@author: SBY
"""
def is_bit_set(int_type, offset):
    mask = 1 << offset
    return not 0 == (int_type & mask)
#设置掩码
def set_bit(int_type, offset):
    return int_type | (1 << offset)

def bytes_to_int(data):
    # note big-endian is the standard network byte order
    return int.from_bytes(data, byteorder='big')
    #bytes类型的变量x，转化为十进制整数
#发送数据的封装，不完整实现，0到125为正常真实长度，重写了一个pack
def pack(data):
    #服务端返回的包，判断data长度，如果大于126则需要兄弟数据报，目前只处理了小于126的
    """pack bytes for sending to client"""
    frame_head = bytearray(2)
    # print(frame_head)  bytearray(b'\x00\x00')
    # set final fragment
    frame_head[0] = set_bit(frame_head[0], 7)
    # set opcode 1 = text
    frame_head[0] = set_bit(frame_head[0], 0)
    # payload length
    assert len(data) < 126, "haven't implemented that yet"
    frame_head[1] = len(data)
    print('test',frame_head[1],frame_head[0],frame_head)
        # add data
    frame = frame_head + data.encode('utf-8')
    return frame

import struct

def pack1(data):
    if data:
        data = data
    else:
        return False
    token = b"\x81"
    length = len(data)
    data = bytes(data,encoding = "utf8")
    print('--------',data)
    if length < 126:    
        print('=========',length,struct.pack("B", length))
        token += struct.pack("B", length)
        
    elif length <= 0xFFFF:
        print('++++++++',length,struct.pack("!BH", 126, length))
        token += struct.pack("!BH", 126, length)
        #token += str(struct.pack("!BH", length), encoding = "utf8")
    else:
        token += struct.pack("!BQ", 127, length)
        #token += str(struct.pack("!BH", length), encoding = "utf8")
     #struct为Python中处理二进制数的模块，二进制流为C，或网络流的形式。
    data = token + data
    #data = bytes(data, encoding = "utf8")
    print(data)
    return data

data = '22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222'
#data = '发送数据，也需要进行处理js 端通过回调函数 ws.onmessage() 接受数据XHR传递   ajax一步实现不刷新的更新，客户端发起第一次握手之后 服务端收到客户端的data，根据mask来对data进行有效数据的提取。toread的用途  entergroup逻辑 mask pack 接收数据的转化  应该和websocket协议有关'
p = pack1(data)
#s = send_data(data)
#test = bytearray(s)
print(p,'这是什么鬼符号')
