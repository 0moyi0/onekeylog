# -><- coding: utf-8 -*-
# 23/07/2022

import re, os
from util import get_file_retxt, get_dict_by_conf, write_log


def get_component_info(log_filename, rawdata_filename, log_cputype_re, raw_cputype_re, args_cpu):
    error_list = []
    errlist = []
    try:
        component_info = {}
        component_info['fw_info'], news = get_fwinfo_bylog(log_filename)
        if news:
            error_list.append((log_filename, news))
        component_info['cpu_dict'], errlist = get_cpudict_byall(log_filename, rawdata_filename, log_cputype_re, raw_cputype_re, args_cpu)
        if errlist:
            error_list.extend(errlist)
    except Exception as e:
        error_list.append((log_filename, str(e)))
        raise e
    return component_info, error_list

def get_fwinfo_bylog(log_filename):
    news = ""
    txt = get_file_retxt(log_filename)
    fw_info = get_dict_by_conf("configuration.py", "fw_info", txt)  # fw_info ： log文件中的version部分数据
    if len(fw_info) == 0:
        news = "Error: Failed to get firmware info from component log."
        write_log(news)    
    return fw_info, news

def get_cpudict_byall(log_filename, rawdata_filename, log_cputype_re, raw_cputype_re, cputype=None):
    error_list = []
    cpu_dict = get_cpuinfo_verid_sockets_bylog(log_filename, log_cputype_re)
    if len(cpu_dict['cpu_info']) == 0:
        news = "Error: Failed to get cpu info from component log."
        write_log(news)
        error_list.append((os.path.basename(log_filename), news))
        cpu_dict, news = get_cpuinfo_verid_sockets_byregrawdata(rawdata_filename, raw_cputype_re, cputype)
        if news:
            error_list.append((os.path.basename(log_filename), news))
    return cpu_dict, error_list

def get_cpuinfo_verid_sockets_bylog(log_name, log_cputype_re):
    txt = get_file_retxt(log_name)
    cpu_type = None
    ver_id = None
    cpu_info = []
    sockets = []
    cpu_dict = {}
    if txt:
        pro_ids = re.findall(log_cputype_re, txt, re.M | re.I)
        ppins = re.findall("ppin: (\w+)", txt, re.M | re.I)
        core_counts = re.findall("proc_used_core_count: (\d+),", txt, re.M | re.I)
        if pro_ids:
            for i in range(len(pro_ids)):
                core_count = hex(int(core_counts[i])) if core_counts else "N/A"
                cpu_info.append({"cpuid":hex(int('0x{}{}{}'.format(pro_ids[i][2], pro_ids[i][1], pro_ids[i][0]), 16)), "ppin":ppins[i], "core_count":core_count})
        if cpu_info:
            if cpu_info[0]['cpuid'].startswith("0x606"):
                cpu_type = "icx"
                ver_id = "1a001"
            elif cpu_info[0]['cpuid'].startswith("0x506"):
                cpu_type = "cpx"
                ver_id = "34001"
            sockets = list(range(len(cpu_info)))
    cpu_dict['cpu_type'], cpu_dict['ver_id'], cpu_dict['sockets'], cpu_dict['cpu_info'] = cpu_type, ver_id, sockets, cpu_info
    return cpu_dict

def get_cpuinfo_verid_sockets_byregrawdata(rawdata_filename, raw_cputype_re, cputype=None):
    cpu_type = None
    ver_id = None
    cpu_info = []
    sockets = []
    cpu_dict = {}
    news = ""
    if get_file_retxt(rawdata_filename):
        txt = get_file_retxt(rawdata_filename)
        cputype_regraw = re.search(raw_cputype_re, txt, re.M | re.I)
        if cputype_regraw:
            cpu_type = cputype_regraw.group(1).lower()
            if cpu_type == 'icx':
                ver_id = "1a001"
                sockets = list(range(2))
            elif cpu_type == 'cpx':
                ver_id = "34001"
                sockets = list(range(4))
            for socket in sockets:
                cpu_info.append({"cpuid": cpu_type, "ppin": "N/A", 'core_count': "N/A"})
    if len(cpu_info) == 0:
        news = "Error: Failed to get CPU type from regrawdata file {0}".format(rawdata_filename)
        write_log(news)
        if cputype:
            cpu_type = cputype
            if cpu_type == 'icx':
                ver_id = "1a001"
                sockets = list(range(2))
            elif cpu_type == 'cpx':
                ver_id = "34001"
                sockets = list(range(4))
            for socket in sockets:
                cpu_info.append({"cpuid": cpu_type, "ppin": "N/A", 'core_count': "N/A"})
        else:
            #logger = logger_cof("onekeylog.log")
            # print("ERROR: Unknown CPU type from the file {0}".format(rawdata_filename))
            write_log("CPU type not found/provided! Skip the log.")
            raise Exception("CPU type not found/provided! Skip the log.")
    cpu_dict['cpu_type'], cpu_dict['ver_id'], cpu_dict['sockets'], cpu_dict['cpu_info'] = cpu_type, ver_id, sockets, cpu_info
    return cpu_dict, news