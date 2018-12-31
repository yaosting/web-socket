# coding=utf-8
'''
file:websockt-server.py
date:2018/12/11 beginchange 14:15
author:mr_yao
email:13761801969@163.com
'''
import socket,json
import hashlib
import threading
from base64 import b64encode

#用户信息存储字典
users={}
#群组信息存储字典
groups={}

#判断是否设置了掩码  到88line前都是为了解决同通信问题
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
def pack1(data):
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
        # add data
    frame = frame_head + data.encode('utf-8')
    return frame

import struct

def pack(data):
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



#接收数据的转换 掩码的第 i%4 位做 xor 运算
#查看报文可得，根据payload表示的数据长度，即msg[1]来得知mask位置，因为服务器接受的信息包含mask加密
def parse_recv_data(msg):
    en_bytes = b''
    cn_bytes = []
    if len(msg) < 6:
        return ''  
    v = msg[1] & 0x7f #16进制127 二进制0111 1111
    if v == 0x7e: #7e 0111 1110
        p = 4
    elif v == 0x7f:
        p = 10
    else:
        p = 2
    mask = msg[p:p + 4]
    data = msg[p + 4:]
    #将可遍历对象像数组列表等组合成一个索引序列，(0, 'Spring'), (1, 'Summer')默认从0开始
    for k, v in enumerate(data):
        nv = chr(v ^ mask[k % 4]) #^按位异或 
        nv_bytes = nv.encode()
        nv_len = len(nv_bytes)
        if nv_len == 1:
            en_bytes += nv_bytes
        else:
            en_bytes += b'%s'
            cn_bytes.append(ord(nv_bytes.decode()))
    if len(cn_bytes) > 2:
        # 字节数组转汉字
        cn_str = ''
        clen = len(cn_bytes)
        count = int(clen / 3)
        for x in range(0, count):
            i = x * 3
            b = bytes([cn_bytes[i], cn_bytes[i + 1], cn_bytes[i + 2]])
            cn_str += b.decode()
        new = en_bytes.replace(b'%s%s%s', b'%s')
        new = new.decode()
        res = (new % tuple(list(cn_str)))
    else:
        res = en_bytes.decode()
    return res

#发送数据
def send_data(dataObj):
    data = json.dumps(dataObj)#转换数据为对象判断数据发送类型（群发或者点对点）
    if data == None or len(data) <= 0:
        return False
    if dataObj['type'] == 'personal':
        userto = dataObj['to']
        userfrom = dataObj['from']
        try:
            users[userto]['conn'].send(pack(data))
        except:
            users[userto]['toRead'].append(data)
            print('aaaaaaaaaaaaaaaaaaa',users[userto]['toRead'])
            ret = {'type': 'server', 'status': 0}
            data = json.dumps(ret)
            users[userfrom]['conn'].send(pack(data))
    if dataObj['type'] == 'group':
        groupto = dataObj['to']
        grps = groups[groupto]
        for user in grps['groupmems']:
            try:
                users[user]['conn'].send(pack(data))
            except:
                print('group Members error')
class WebSocket(threading.Thread):  # 继承Thread

    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, conn, name, remote, path="/"):
        threading.Thread.__init__(self)  # 初始化父类Thread
        self.conn = conn
        self.name = name
        self.remote = remote
        self.path = path
        self.buffer = ""

    def run(self):
        headers = {}
        self.handshaken = False
        while True:
            if self.handshaken == False:
                print('Start Handshaken with {}!'.format(self.remote),self.conn,self.name)
                self.buffer += bytes.decode(self.conn.recv(1024))#将前端发送的json数据转为betys
                if self.buffer.find('\r\n\r\n') != -1:
                    header, data = self.buffer.split('\r\n\r\n', 1)
                    for line in header.split("\r\n")[1:]:
                        key, value = line.split(": ", 1)
                        headers[key] = value

                    headers["Location"] = ("ws://%s%s" % (headers["Host"], self.path))
                    key = headers['Sec-WebSocket-Key']
                    token = b64encode(hashlib.sha1(str.encode(str(key + self.GUID))).digest())

                    handshake = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + bytes.decode(
                        token) + "\r\nWebSocket-Origin: " + str(headers["Origin"]) + "\r\nWebSocket-Location: " + str(
                        headers["Location"]) + "\r\n\r\n"

                    self.conn.send(str.encode(str(handshake)))#发送握手信息
                    self.handshaken = True
                    print('Handshaken with {} success!'.format(self.remote))

            else:
                all_data = self.conn.recv(1024)
                #print('获得的全部数据',all_data,'全部数据结束')
                data=parse_recv_data(all_data)

                if not len(all_data):
                    return False
                else:
                    try:
                        #以下为各种请求的处理（登录、注册、创建群组、发送消息等）
                        #print('获取的数据',data,'获取数据结束')
                        #nowTime = time.strftime('%H:%M:%S', time.localtime(time.time()))
                        dataObj = json.loads(data)
                        if dataObj['type'] == 'quit':
                            quituser = dataObj['username']
                            print('User %s Logout!' % (quituser))
                            users[quituser]['status'] = 0
                            del users[quituser]['conn']
                            self.conn.close()
                            return False
                        if (dataObj['type'] == 'login'):
                            regUser = dataObj['username']
                            retStatus = 0
                            try:
                                if users[regUser] and users[regUser]['password'] == dataObj['password']:
                                    if users[regUser]['status'] == 1:
                                        retStatus = 2
                                    else:
                                        users[regUser]['status'] = 1
                                        #toRead = users[regUser]['toRead']
                                        #dataObj = {"type":"login","status":0,"toRead":'~'.join(toRead)}
                                        users[regUser]['toRead'] = []
                                        users[regUser]['conn'] = self.conn
                                else:
                                    retStatus = 1
                            except:
                                retStatus = 1
                            finally:
                                dataObj = {"type": "login", "status": retStatus}
                                data = json.dumps(dataObj)
                                self.conn.send(pack(data))#传入一个json数据 处理成bytes的包格式
                            continue
                        if (dataObj['type'] == 'reg'):
                            regUser = dataObj['username']
                            if regUser in users:
                                dataObj = {"type": "reg", "status": 1}
                            else:
                                #字典嵌套字典 用户字典结构
                                users[regUser] = {'password':dataObj['password'],'conn':self.conn,'status':0,'friends':[],'groups':[],'toRead':[]}
                                dataObj = {"type":"reg","status":0}
                                users[regUser]['status'] = 1
                            data = json.dumps(dataObj)
                            self.conn.send(pack(data))
                            continue
                        if (dataObj['type'] == 'addFriend'):
                            username = dataObj['username']
                            friendname = dataObj['target']
                            if friendname not in users[username]['friends']:
                                users[username]['friends'].append(friendname);
                                users[friendname]['friends'].append(username);
                                dataObj = {"type": "addFriend", "status": 0}
                            else:
                                dataObj = {"type":"reg","status":1}
                            data = json.dumps(dataObj)
                            self.conn.send(pack(data))
                            continue
                        if (dataObj['type'] == 'search'):
                            keywords = dataObj['keywords']
                            gps=[];persons=[]
                            for g in groups:
                                if keywords in g:
                                    gps.append(g)
                            for p in users:
                                if keywords in p:
                                    persons.append(p)
                            dataObj={"type":"search",'groups':gps,'persons':persons}
                            data = json.dumps(dataObj)
                            self.conn.send(pack(data))
                            continue
                        if (dataObj['type'] == 'enterGroup'):##########
                            gname = dataObj['target']
                            uname = dataObj['username']
                            if uname not in groups[gname]['groupmems']:
                                groups[gname]['groupmems'].append(uname)
                                users[uname]['groups'].append(gname)
                                dataObj = {"type": "enterGroup", "status": 0}
                            else:
                                dataObj = {"type": "enterGroup", "status": 1}
                            data = json.dumps(dataObj)
                            self.conn.send(pack(data))
                            continue
                        if (dataObj['type'] == 'getGroups'):#获取群组信息 下同 应该对应于群组图标点击事件
                            uname = dataObj['username']
                            if uname in users:
                                dataObj = {"type": "getGroups", "status": 0,'list':users[uname]['groups']}
                                print('------',users[uname]['groups'])
                            else:
                                dataObj = {"type":"getGroups","status":1}
                            data = json.dumps(dataObj)
                            self.conn.send(pack(data))
                            continue
                        if (dataObj['type'] == 'getFriends'):
                            uname = dataObj['username']
                            if uname in users:
                                dataObj = {"type": "getFriends", "status": 0,'list':users[uname]['friends']}
                            else:
                                dataObj = {"type":"getFriends","status":1}
                            data = json.dumps(dataObj)
                            self.conn.send(pack(data))
                            continue
                        if (dataObj['type'] == 'addgroup'):
                            owner = dataObj['username']
                            groupname = dataObj['groupName']
                            groupmotto = dataObj['groupMotto']#群组座右铭
                            groupmems = dataObj['groupMems']#群组成员 多个通过切片来分开
                            if groupname in groups: ########此处判断不妥 应该在自己的群组下找
                                dataObj = {"type": "addgroup", "status": 1}
                            else:
                                members=groupmems.split(',')
                                #群组字典结构
                                groups[groupname] = {'owner':owner,'groupname':groupname,'groupmotto':groupmotto,'groupmems':members}
                                #'groupmems':members
                                dataObj = {"type":"addgroup","status":0}
                                for user in members:
                                    users[user]['groups'].append(groupname)
                                    print('群组中每个成员的变动',users[user]['groups'])
                                print('成员',members,'此群组',groups[groupname])
                            data = json.dumps(dataObj)
                            self.conn.send(pack(data))
                            continue
                        send_data(dataObj)
                    except:
                        print('Something wrong!')


class WebSocketServer(object):
    def __init__(self):
        self.socket = None

    def begin(self):
        print('WebSocketServer Start!')
        print('当前运行的线程数为：%d'%threading.active_count())
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 8899))
        self.socket.listen(50)
        #创建套接字，并监听
        while True:
            connection, address = self.socket.accept()
            #第一个元素connection是新的socket对象，服务器必须通过它与客户通信；第二个元素 address是客户的Internet地址
            username = "user-" + str(address[1])
            newSocket = WebSocket(connection, username, address)
            newSocket.start()  # 开始线程,执行run函数
            #length=len(threading.enumerate())#枚举返回个列表
            #print('当前运行的线程数为：%d'%threading.active_count())
            #time.sleep(50)

if __name__ == "__main__":
    server = WebSocketServer()
    server.begin()
    


