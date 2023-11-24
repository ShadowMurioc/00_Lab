from tools.timestamps_decoder import func_decode_pcap
import os
import re
import shutil

'''
exact-capture -m 100000  -k -i exanic0:0 -i exanic0:1 -o /data0/hft_capture -c 0:1,2:3,4
-m 100000  每100k自动转存储成一个文件 【可以根据实际的需求 调大或者调小】

初步需求，周期性的将数据包存储到 /analysis目录下
解析后，将解析后的数据包放到done目录下 【已实现的需求】

v20231124: Add HKEX Quote SN，NIC Port ID
            Add MT value, 未实际校验. 为了保障数据的准确.过滤条件需要修改成实际的TCP 端口, # Line 90

'''

cur_dir = os.getcwd()
src_dir = cur_dir + '/analysis'
filelist = os.listdir(src_dir)
dest_dir = cur_dir + '/done'


def natural_sort_key(s):
    """
    按文件名的结构排序，即依次比较文件名的非数字和数字部分
    """
    # 将字符串按照数字和非数字部分分割，返回分割后的子串列表
    sub_strings = re.split(r'(\d+)', s)
    # 如果当前子串由数字组成，则将它转换为整数；否则返回原始子串
    sub_strings = [int(c) if c.isdigit() else c for c in sub_strings]
    # 根据分割后的子串列表以及上述函数的返回值，创建一个新的列表
    # 按照数字部分从小到大排序，然后按照非数字部分的字典序排序
    return sub_strings


sorted_file_list = sorted(filelist, key=natural_sort_key)


for filename in sorted_file_list:
    os.chdir(src_dir)
    if 'expcap' in filename:
        func_decode_pcap(filename, 'exact')
        # shutil.move(filename, dest_dir)
    if 'metawatch' in filename:
        func_decode_pcap(filename, 'metawatch')
        shutil.move(filename, dest_dir)

