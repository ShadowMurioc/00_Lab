import sys
import datetime

from prettytable import *
from scapy.error import Scapy_Exception
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.compat import raw


def func_decode_pcap(filename, filetype):
    print('解析 ' + filename + ' ...')
    # 数据包数量计算
    Total_Count = 0
    ICMP_Count = 0
    TCP_Count = 0
    UDP_Count = 0
    # 格式化输出
    decoder_table = PrettyTable()
    decoder_table.field_names = ['序号', '捕获帧长度', 'SN', '源地址', '目的地址', '协议',
                                 '标识符', '设备标识', '端口序号', 'UTC时间', '时间戳',
                                 '双精度时间']
    # 设置表格样式
    # table.set_style(MSWORD_FRIENDLY)
    try:
        for (Hex_Data, Hex_tMetaData) in RawPcapReader(filename):
            TimestampSecond = '---'
            UTC_TimeStamp = '---'
            TimestampFractionalSecond = '---'
            NIC_DeviceID = '---'
            NIC_SourcePortID = '---'
            Total_Count += 1
            All_Packet = Ether(Hex_Data)
            SN = '---'



            if 'type' not in All_Packet.fields:
                continue
            if All_Packet.type != 0x0800:
                continue
            # UTC 时间计算 ， 截取Tailler部分
            match filetype:
                case 'exact':
                    ByteArray = bytearray.fromhex(raw(Hex_Data)[-16:-12].hex())
                    ByteArray.reverse()
                    TimestampSecond = int(ByteArray.hex(), 16)
                    # 双精度时间计算
                    ByteArray = bytearray.fromhex(raw(Hex_Data)[-12:-7].hex())
                    ByteArray.reverse()
                    TimestampFractionalSecond = int(ByteArray.hex(), 16)
                    if len(str(TimestampFractionalSecond)) < 12:
                        strzero = '0' * (12 - len(str(TimestampFractionalSecond)))
                        TimestampFractionalSecond = strzero + str(TimestampFractionalSecond)
                    UTC_TimeStamp = str(datetime.datetime.utcfromtimestamp(TimestampSecond)) + '.' \
                                    + str(TimestampFractionalSecond)
                    NIC_DeviceID = int(raw(Hex_Data)[-6:-5].hex(), 16)
                    NIC_SourcePortID = int(raw(Hex_Data)[-5:-4].hex(), 16)

                case 'metawatch':
                    ByteArray = bytearray.fromhex(raw(Hex_Data)[-12:-8].hex())
                    # print(ByteArray)
                    TimestampSecond = int(ByteArray.hex(), 16)
                    # 双精度时间计算
                    ByteArray = bytearray.fromhex(raw(Hex_Data)[-8:-4].hex())
                    TimestampFractionalSecond = int(ByteArray.hex(), 16)
                    if len(str(TimestampFractionalSecond)) < 9:
                        strzero = '0' * (9 - len(str(TimestampFractionalSecond)))
                        TimestampFractionalSecond = strzero + str(TimestampFractionalSecond)
                    UTC_TimeStamp = str(datetime.datetime.utcfromtimestamp(TimestampSecond)) + '.' \
                                    + str(TimestampFractionalSecond)
                    NIC_DeviceID = int(raw(Hex_Data)[-3:-1].hex(), 16)
                    NIC_SourcePortID = raw(Hex_Data)[-1]
            IP_Packet = All_Packet[IP]
            if IP_Packet.dst == "255.255.255.255":
                continue
            match IP_Packet.proto:
                case 1:
                    ICMP_Count += 1
                    ICMP_Data = [filename + '--Frame-' + str(Total_Count), len(Hex_Data), SN, IP_Packet.src, IP_Packet.dst,
                                 'ICMP',
                                 hex(IP_Packet.id), NIC_DeviceID, NIC_SourcePortID, UTC_TimeStamp, TimestampSecond,
                                 TimestampFractionalSecond]
                    decoder_table.add_row(ICMP_Data)
                case 6:
                    TCP_Count += 1
                    TCP_Data = [filename + '--Frame-' + str(Total_Count), len(Hex_Data), SN, IP_Packet.src, IP_Packet.dst,
                                'TCP',
                                hex(IP_Packet.id), NIC_DeviceID, NIC_SourcePortID, UTC_TimeStamp, TimestampSecond,
                                TimestampFractionalSecond]
                    decoder_table.add_row(TCP_Data)
                case 17:
                    UDP_Data = All_Packet[UDP]
                    ByteArray = bytearray.fromhex(raw(UDP_Data)[12:16].hex())
                    ByteArray.reverse()
                    SN = int(ByteArray.hex(), 16)

                    UDP_Count += 1
                    UDP_Data = [filename + '--Frame-' + str(Total_Count), len(Hex_Data), SN, IP_Packet.src, IP_Packet.dst,
                                'UDP',
                                hex(IP_Packet.id), NIC_DeviceID, NIC_SourcePortID, UTC_TimeStamp, TimestampSecond,
                                TimestampFractionalSecond]
                    decoder_table.add_row(UDP_Data)

        print('抓包文件解析完成.'
              'Total Packets: ' + str(Total_Count) + '，' +
              'Total ICMP Packets: ' + str(ICMP_Count) + '，' +
              'Total TCP Packets: ' + str(TCP_Count) + '，' +
              'Total UDP Packets: ' + str(UDP_Count)
              )

    except Scapy_Exception as e:
        sys.exit('The script terminated unexceptedly, please check error message: ' + str(e))

    print(decoder_table)
