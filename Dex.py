#-*- coding: utf-8 -*-
import mmap
import struct
import hashlib
import String_infos

class Dex :
    def __init__ (self,dexfieName) :
        self.mm = ''
        self.dexFile = dexfieName
        self.hedr = ''
        self.ids_list = []
        self.type_list = []
    def openDex (self):
        fp = open(self.dexFile, 'rb')
        self.mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

    def check_dex(self):
        '''
            헤더가 'dex' 문자열로 시작하면서 최소 크기가 0x70 Byte 보다 커야 함
            :return
        '''
        if self.mm[0:3] == 'dex' and len(self.mm) > 70 :
            return True
        return False

    def setHeader(self):
        magic = self.mm[0:8]
        checksum = struct.unpack('<L', self.mm[8:0xC])[0]
        sha1 = self.mm[0xC:0x20]
        file_size = struct.unpack('<L', self.mm[0x20:0x24])[0]
        header_size = struct.unpack('<L', self.mm[0x24:0x28])[0]
        endian_tag = struct.unpack('<L', self.mm[0x28:0x2C])[0]
        link_size = struct.unpack('<L', self.mm[0x2C:0x30])[0]
        link_off = struct.unpack('<L', self.mm[0x30:0x34])[0]
        map_off = struct.unpack('<L', self.mm[0x34:0x38])[0]
        string_ids_size = struct.unpack('<L', self.mm[0x38:0x3C])[0]
        string_ids_off = struct.unpack('<L', self.mm[0x3C:0x40])[0]
        type_ids_size = struct.unpack('<L', self.mm[0x40:0x44])[0]
        type_ids_off = struct.unpack('<L', self.mm[0x44:0x48])[0]
        proto_ids_size = struct.unpack('<L', self.mm[0x48:0x4C])[0]
        proto_ids_off = struct.unpack('<L', self.mm[0x4C:0x50])[0]
        field_ids_size = struct.unpack('<L', self.mm[0x50:0x54])[0]
        field_ids_off = struct.unpack('<L', self.mm[0x54:0x58])[0]
        method_ids_size = struct.unpack('<L', self.mm[0x58:0x5C])[0]
        method_ids_off = struct.unpack('<L', self.mm[0x5C:0x60])[0]
        class_defs_size = struct.unpack('<L', self.mm[0x60:0x64])[0]
        class_defs_off = struct.unpack('<L', self.mm[0x64:0x68])[0]
        data_size = struct.unpack('<L', self.mm[0x68:0x6C])[0]
        data_off = struct.unpack('<L', self.mm[0x6C:0x70])[0]

        hdr = {}

        # print "header size : ", hex(header_size)
        if len(self.mm) != file_size:  # 헤더에 기록된 파일 크기 정보와 실제 파일의 크기가 다르면 분석을 종료한다.
            return hdr

        hdr['magic'] = magic
        hdr['checksum'] = checksum
        hdr['sha1'] = sha1
        hdr['file_size'] = file_size
        hdr['header_size'] = header_size
        hdr['endian_tag'] = endian_tag  # little endian or Big endian info
        hdr['link_size'] = link_size
        hdr['link_off'] = link_off
        hdr['map_off'] = map_off  # Location of file map
        hdr['string_ids_size'] = string_ids_size
        hdr['string_ids_off'] = string_ids_off
        hdr['type_ids_size'] = type_ids_size
        hdr['type_ids_off'] = type_ids_off
        hdr['proto_ids_size'] = proto_ids_size
        hdr['proto_ids_off'] = proto_ids_off
        hdr['field_ids_size'] = field_ids_size
        hdr['field_ids_off'] = field_ids_off
        hdr['method_ids_size'] = method_ids_size
        hdr['method_ids_off'] = method_ids_off
        hdr['class_defs_size'] = class_defs_size
        hdr['class_defs_off'] = class_defs_off
        hdr['data_size'] = data_size
        hdr['data_off'] = data_off
        self.hedr =hdr


    def setString_ids(self,count):
        '''
            :param header_info: dex binary header info
            :param mm: load dex binary
            :param count: check info
            :return: #off는 String의 숫자를 가지고 있다. off위치에서 다음칸부터 off에 저장된 수만큼이 String 문자 내용이다.
        '''

        ids_list = []
        start = self.hedr[String_infos.ids_offsetList[count]]
        for i in range(self.hedr[String_infos.ids_sizeList[count]]):
            off = struct.unpack('<L', self.mm[start + 4 * i:start + 4 + 4 * i])[0]
            c_size = ord(self.mm[off])
            c_char = self.mm[off + 1: off + 1 + c_size]
            ids_list.append(c_char)
        self.ids_list = ids_list
    def getString_ids(self):
        return self.ids_list

    def setType_ids(self, count):
        '''
        :param header_info:
        :param mm:
        :param count:
        :return: type list index
        '''
        type_list = []  # 전체 Type 정보를 담을 리스트
        start = self.hedr[String_infos.ids_offsetList[count]]

        for i in range(self.hedr[String_infos.ids_sizeList[count]]):
            idx = struct.unpack('<L', self.mm[start + (i * 4):start + (i * 4) + 4])[0]
            type_list.append(idx)
        self.type_list = type_list

    def getType_ids(self):
        return self.type_list

if __name__ == "__main__" :
    fileName = "test.dex"
    dex = Dex(fileName)
    dex.openDex()
    check = dex.check_dex()

    if (check == False) :
        print 'bye'
        exit()
    dex.setHeader()
    dex.setString_ids(0)
    string_idsList = dex.getString_ids()
    print 'String list info'
    for i in range(len(string_idsList)):
        print '[%4d] %s' % (i, string_idsList[i])

    dex.setType_ids(1)

    type_idsList = dex.getType_ids()
    print 'type list info'
    for i in range(len(type_idsList)):
        string_idx = type_idsList[i]
        print '[%4d] %s' % (i, string_idsList[string_idx])