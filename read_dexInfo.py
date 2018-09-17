#-*- coding: utf-8 -*-
import mmap
import struct
import hashlib


#fp = open('classes.dex', 'rb')
fp = open('test.dex', 'rb')
mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

#---------------------------------------------------------------------
# TEST
#---------------------------------------------------------------------
#print mm



# 헤더가 'dex' 문자열로 시작하면서 최소 크기가 0x70 Byte 보다 커야 함
def isdex(mm) :
    if mm[0:3] == 'dex' and len(mm) > 0x70 :
        return True

    return False

#---------------------------------------------------------------------
# TEST
#---------------------------------------------------------------------
#print isdex(mm)

'''
magic 8byte
checksum = 4byte
sha =  20byte
file_size = 4byte
header_size = 4byte
'''

headerList = ['magic','checksum','sha1','file_size','header_size','endian_tag','link_size',
              'link_off','map_off','string_ids_size','string_ids_off','proto_ids_size',
              'type_ids_off','type_ids_size','type_ids_off','proto_ids_size','proto_ids_off',
              'method_ids_size','method_ids_off','class_defs_size','class_defs_off','data_size',
              'data_off'
              ]

#-----------------------------------------------------------------
# header : dex 파일의 헤더를 파싱한다.
#-----------------------------------------------------------------
def header(mm) :

    magic           = mm[0:8]
    checksum        = struct.unpack('<L', mm[8:0xC])[0]
    sha1             = mm[0xC:0x20]
    file_size       = struct.unpack('<L', mm[0x20:0x24])[0]
    header_size     = struct.unpack('<L', mm[0x24:0x28])[0]
    endian_tag      = struct.unpack('<L', mm[0x28:0x2C])[0]
    link_size       = struct.unpack('<L', mm[0x2C:0x30])[0]
    link_off        = struct.unpack('<L', mm[0x30:0x34])[0]
    map_off         = struct.unpack('<L', mm[0x34:0x38])[0]
    string_ids_size = struct.unpack('<L', mm[0x38:0x3C])[0]
    string_ids_off  = struct.unpack('<L', mm[0x3C:0x40])[0]
    type_ids_size   = struct.unpack('<L', mm[0x40:0x44])[0]
    type_ids_off    = struct.unpack('<L', mm[0x44:0x48])[0]
    proto_ids_size  = struct.unpack('<L', mm[0x48:0x4C])[0]
    proto_ids_off   = struct.unpack('<L', mm[0x4C:0x50])[0]
    field_ids_size  = struct.unpack('<L', mm[0x50:0x54])[0]
    field_ids_off   = struct.unpack('<L', mm[0x54:0x58])[0]
    method_ids_size = struct.unpack('<L', mm[0x58:0x5C])[0]
    method_ids_off  = struct.unpack('<L', mm[0x5C:0x60])[0]
    class_defs_size = struct.unpack('<L', mm[0x60:0x64])[0]
    class_defs_off  = struct.unpack('<L', mm[0x64:0x68])[0]
    data_size       = struct.unpack('<L', mm[0x68:0x6C])[0]
    data_off        = struct.unpack('<L', mm[0x6C:0x70])[0]

    hdr = {}

    #print "header size : ", hex(header_size)
    if len(mm) != file_size : # 헤더에 기록된 파일 크기 정보와 실제 파일의 크기가 다르면 분석을 종료한다.
        return hdr

    hdr['magic'          ] = magic
    hdr['checksum'       ] = checksum
    hdr['sha1'            ] = sha1
    hdr['file_size'      ] = file_size
    hdr['header_size'    ] = header_size
    hdr['endian_tag'     ] = endian_tag # little endian or Big endian info
    hdr['link_size'      ] = link_size
    hdr['link_off'       ] = link_off
    hdr['map_off'        ] = map_off # Location of file map
    hdr['string_ids_size'] = string_ids_size
    hdr['string_ids_off' ] = string_ids_off
    hdr['type_ids_size'  ] = type_ids_size
    hdr['type_ids_off'   ] = type_ids_off
    hdr['proto_ids_size' ] = proto_ids_size
    hdr['proto_ids_off'  ] = proto_ids_off
    hdr['field_ids_size' ] = field_ids_size
    hdr['field_ids_off'  ] = field_ids_off
    hdr['method_ids_size'] = method_ids_size
    hdr['method_ids_off' ] = method_ids_off
    hdr['class_defs_size'] = class_defs_size
    hdr['class_defs_off' ] = class_defs_off
    hdr['data_size'      ] = data_size
    hdr['data_off'       ] = data_off

    return hdr

ids_offsetList = ['string_ids_off','type_ids_off','proto_ids_off','field_ids_off',
                  'method_ids_off','class_defs_off','data_off']
ids_sizeList = ['string_ids_size','type_ids_size','proto_ids_size','field_ids_size',
                  'method_ids_size','class_defs_size','data_size']

acces_list = [0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80,0x100,
              0x200,0x400,0x800,0x1000,0x2000,0x4000,0x8000,
              0x10000,0x20000]

##TODO 데이터 사이즈 영역에서 에러 발생
#def get_dexIDS(header_info,mm,count) :


#String 정보를 확인 할 수 있다.
def getString_ids (header_info,mm,count) :
    '''
        :param header_info: dex binary header info
        :param mm: load dex binary
        :param count: check info
        :return: #off는 String의 숫자를 가지고 있다. off위치에서 다음칸부터 off에 저장된 수만큼이 String 문자 내용이다.
    '''

    ids_list = []
    start = header_info[ids_offsetList[count]]
    for i in range(header_info[ids_sizeList[count]]):

        off = struct.unpack('<L', mm[start + 4 * i:start + 4 + 4 * i])[0]
        c_size = ord(mm[off])
        c_char = mm[off + 1: off + 1 + c_size]
        ids_list.append(c_char)

    return ids_list

def getType_ids (header_info, mm,count):
    '''
    :param header_info:
    :param mm:
    :param count:
    :return: type list index
    '''
    type_list = []  # 전체 Type 정보를 담을 리스트
    start = header_info[ids_offsetList[count]]

    for i in range(header_info[ids_sizeList[count]]):
        idx = struct.unpack('<L', mm[start + (i * 4):start + (i * 4) + 4])[0]
        type_list.append(idx)

    return type_list

def getProto_id_list(header_info,mm,count) :
    '''
        :param hdr:
        :param mm:
        :param count:
        :return:
    '''
    proto_list = []
    start = header_info[ids_offsetList[count]]

    for i in range(header_info[ids_sizeList[count]]) :
        shorty_idx      = struct.unpack('<L', mm[start+(i*12)  :start+(i*12)+ 4])[0]
        return_type_idx = struct.unpack('<L', mm[start+(i*12)+4:start+(i*12)+ 8])[0]
        param_off       = struct.unpack('<L', mm[start+(i*12)+8:start+(i*12)+12])[0]
        proto_list.append([shorty_idx, return_type_idx, param_off])
    return proto_list

def getField_id_list(header_info, mm, count) :
    '''
        :param header_info:
        :param mm:
        :param count:
        :return:
    '''
    field_list = []

    start = header_info[ids_offsetList[count]]

    for i in range(header_info[ids_sizeList[count]]) :
        class_idx = struct.unpack('<H', mm[start+(i*8)  :start+(i*8)+2])[0]
        type_idx  = struct.unpack('<H', mm[start+(i*8)+2:start+(i*8)+4])[0]
        name_idx  = struct.unpack('<L', mm[start+(i*8)+4:start+(i*8)+8])[0]

        field_list.append([class_idx, type_idx, name_idx])

    return field_list

def getMethod_id_list(header_info, mm, count):
    method_list = []

    start = header_info[ids_offsetList[count]]

    for i in range(header_info[ids_sizeList[count]]):
        class_idx = struct.unpack('<H', mm[start + (i * 8):start + (i * 8) + 2])[0]
        proto_idx = struct.unpack('<H', mm[start + (i * 8) + 2:start + (i * 8) + 4])[0]
        name_idx = struct.unpack('<L', mm[start + (i * 8) + 4:start + (i * 8) + 8])[0]

        method_list.append([class_idx, proto_idx, name_idx])

    return method_list

def getClass_id_list(header_info, mm, count) :
    class_list = []

    start = header_info[ids_offsetList[count]]

    for i in range(header_info[ids_sizeList[count]]):
        class_idx = struct.unpack('<L', mm[start + (i * 32) :start + (i * 32) + 4])[0]
        access_flags = struct.unpack('<L', mm[start + (i * 32) +4 :start + (i * 32) + 8])[0]
        superclass_idx = struct.unpack('<L', mm[start + (i * 32)+8:start + (i * 32) + 12])[0]
        interface_off = struct.unpack('<L', mm[start + (i * 32)+12:start + (i * 32) + 16])[0]
        source_file_idx = struct.unpack('<L', mm[start + (i * 32)+16:start + (i * 32) + 20])[0]
        annotations_off = struct.unpack('<L', mm[start + (i * 32)+20:start + (i * 32) + 24])[0]
        class_data_off = struct.unpack('<L', mm[start + (i * 32)+24:start + (i * 32) + 28])[0]
        static_values_off = struct.unpack('<L', mm[start + (i * 32)+28:start + (i * 32) + 32])[0]

        class_list.append([class_idx, access_flags, superclass_idx, interface_off, source_file_idx, annotations_off,class_data_off ,static_values_off])

    return class_list
#---------------------------------------------------------------------
# TEST
#---------------------------------------------------------------------

## class_def

list_access = [0x20000,0x10000,0x8000,0x4000,0x2000
               ,0x1000 ,0x800,0x400,0x200, 0x100
                ,0x80,0x40,0x20,0x10,0x8,0x4,0x2,0x1]

###
###
###
###
##class
class_String = ['','','','','','','','abstract','interface'
    , '','','','','','','final','static','protected','private','public']
##field
field_String = ['','','','','','','','',''
    , '','','transient','','volatitle','','final','static','protected','private','public']
##method
method_String = ['','constructor','','','','','strictfp','abstract',''
    , 'native','가변인자','','','','synchromized','final','static','protected','private','public']

def get_acces_flag_info(access_flags,String_type):

    string = []
    return_st = []
    if String_type == 0 :
        string = class_String

    elif String_type == 1 :
        string = field_String
    else :
        string = method_String

    #print "access_flag : ",hex(access_flags)
    for i in range(len(list_access)) :
        if access_flags > list_access[i] :
            access_flags -=list_access[i]
            return_st.append(string[i])
        elif access_flags < list_access[i] :
            continue

        elif access_flags == list_access[i] :
            return_st.append(string[i])
            break



    return return_st
#print hdr.keys()



#for i in headerList :
#    print i #," : ",hdr[i]
if __name__ == "__main__" :

    hdr = header(mm)
    #print 'file size : ',hex(hdr['file_size'])
    #print 'endian_tag : ',hex(hdr['endian_tag'])

    string_idsList = getString_ids (hdr, mm, 0)

    print 'String list info'
    for i in range(len(string_idsList)):
        print '[%4d] %s' % (i, string_idsList[i])


    type_idsList = getType_ids(hdr, mm, 1)

    print 'type list info'
    for i in range(len(type_idsList)):
        string_idx = type_idsList[i]
        print '[%4d] %s' % (i, string_idsList[string_idx])

    proto_idsList =getProto_id_list(hdr,mm,2)

    print 'proto list info'


    for i in range(len(proto_idsList)):
        (string_idx, type_idx, parameter_off) = proto_idsList[i]


        string_str = string_idsList[string_idx]
        type_str = string_idsList[type_idsList[type_idx]]

        if parameter_off == 0x0 :
            parameter_num = 0
        else :
            parameter_num = struct.unpack('<L', mm[parameter_off:parameter_off + 4])[0]



        # method 인자 정보 , return type , parameter 정보
        msg = '%s %s [%d]' % (string_str, type_str, parameter_num)
        print '[%4d] %s' % (i, msg)

        #parameter info
        if parameter_num != 0 :
            for j in range(parameter_num):
                parameter_type = struct.unpack('<H', mm[parameter_off:parameter_off + 2])[0]
                msg = '%s' %(string_idsList[type_idsList[parameter_type]])
                print '  - %s' %(msg)
                parameter_off += 2



    field_idsList = getField_id_list(hdr, mm, 3)

    # 전체 문자열 출력하기

    print 'field list info'
    for i in range(len(field_idsList)):
        (class_idx, type_idx, name_idx) = field_idsList[i]

        class_str = string_idsList[type_idsList[class_idx]] #클래스 이름
        type_str = string_idsList[type_idsList[type_idx]]   #필드의 종류
        name_str = string_idsList[name_idx]                 #필드의 이름

        msg = '%s   %s  %s' % (class_str , type_str, name_str)
        print '[%4d] %s' % (i, msg)


    method_idsList = getMethod_id_list(hdr, mm, 4)

    print 'method list info'
    for i in range(len(method_idsList)):
        (class_idx, proto_idx, name_idx) = method_idsList[i]

        class_str = string_idsList[type_idsList[class_idx]] #클래스 이름
        name_str  = string_idsList[name_idx]


        msg = '%s  %s' % (class_str, name_str)
        print '[%4d] %s' % (i, msg)

        (string_idx, type_idx, parameter_off) = proto_idsList[proto_idx]
        string_str = string_idsList[string_idx]  # 필드의 종류
        type_str = string_idsList[type_idsList[type_idx]]


        if parameter_off == 0x0:
            parameter_num = 0
        else:
            parameter_num = struct.unpack('<L', mm[parameter_off:parameter_off + 4])[0]

        msg = '%s %s [%d]' % (string_str, type_str, parameter_num)
        print '  [ %s ]' % (msg)
        # parameter info
        if parameter_num != 0:
            for j in range(parameter_num):
                parameter_type = struct.unpack('<H', mm[parameter_off:parameter_off + 2])[0]
                msg = '%s' % (string_idsList[type_idsList[parameter_type]])
                print '  - %s' % (msg)
                parameter_off += 2

    class_idsList = getClass_id_list(hdr, mm, 5)

    print 'class list info'
    for i in range(len(class_idsList)):
        (class_idx, access_flags, superclass_idx, interface_off,
         source_file_idx, annotations_off,class_data_off, static_values_off) = class_idsList[i]

        class_str = string_idsList[type_idsList[class_idx]]  # 클래스 이름
        ret_access_data = get_acces_flag_info(access_flags, 0)
        superclass_str = string_idsList[type_idsList[superclass_idx]]

        if interface_off == 0x0:
            interface_num = 0
        else:
            interface_num = struct.unpack('<L', mm[interface_off:interface_off + 4])[0]

        #msg = 'interface num [%d]' % (parameter_num)

        source_file_str = '알수없음'
        print "source_file_idx" , source_file_idx
        if source_file_idx !=4294967295 :
            source_file_str = string_idsList[int(source_file_idx)]

        if annotations_off == 0x0:
            annotations_num = 0
        else:
            annotations_num = struct.unpack('<L', mm[annotations_off:annotations_off + 4])[0]

        print "class str : " ,class_str

        for i in range(len(ret_access_data)):
            print "     acces_flag[%d] : %s" %(i, ret_access_data[i])
        print "superclass_str : ",superclass_str

        print "inter face ",interface_num
        if interface_num != 0:

            for j in range(interface_num):
                interface_type = struct.unpack('<H', mm[interface_off:interface_off + 2])[0]
                msg = '%s' % (string_idsList[type_idsList[interface_type]])
                print '           - %s' % (msg)
                interface_off += 4

        print "source_file_str : ",source_file_str
        print 'annotations_off : ', hex(annotations_off)
        print 'class_data_off : ',hex(class_data_off)
        print 'static_values_off : ', hex(static_values_off)
