# -><- coding: utf-8 -*-
# 23/07/2022

import argparse
import json
import os
import re
from collections import OrderedDict
from parse_analy_report import deal_report
from parse_component_log import get_cpudict_byall, get_fwinfo_bylog
from util import _read_json, merge_dic, get_inspur_reg_map, make_file, write_log


# convert the regrawdata file to the ACD file.
def deal_regrawdata(rawdata_filename, component_info, all_list=[]):
    cpu_dict, fw_info = component_info['cpu_dict'], component_info['fw_info']
    # cpu_type, ver_id, sockets, cpu_info = get_cputype_verid_sockets(log_filename, rawdata_filename, log_cputype_re, raw_cputype_re, args_cpu)
    cpu_type, ver_id, sockets, cpu_info = cpu_dict['cpu_type'], cpu_dict['ver_id'], cpu_dict['sockets'], cpu_dict['cpu_info']
    datas = []
    error_list = []
    if os.path.exists(rawdata_filename):
        raw_datas, error_list = _read_json(rawdata_filename)
        if 'RegisterDataLog' in raw_datas:
            datas = raw_datas.get("RegisterDataLog", None)
    else:
        #logger = logger_cof("onekeylog.log")
        news = "Warning: RegRawData file "+os.path.basename(rawdata_filename)+ " not found."
        write_log(news)
        #error_list.append(news)
        # print(rawdata_filename, "Warning: No RegRawData file found.")
    i = 0
    try:
        if datas:
            for log in datas:
                new_crashdump = OrderedDict()
                # Create first level hierarchy
                new_crashdump['METADATA'] = OrderedDict()
                new_crashdump['PROCESSORS'] = OrderedDict()
                new_crashdump['METADATA']['_version'] = '0x0b0' + ver_id
                new_crashdump['METADATA']['crashdump_version'] = 'Inspur_Onekeylog_Conversion'
                new_crashdump['METADATA']['bmc_fw_version'] = 'N/A'
                new_crashdump['METADATA']['bios_id'] = 'N/A'
                new_crashdump['METADATA']['me_fw_ver'] = 'N/A'
                new_crashdump['METADATA']['platform_name'] = "N/A"
                new_crashdump['METADATA']['CollectIntegrity'] = 0
                for fw in fw_info:  # fw_info ： the fw_info(firmware versions) data in component.log
                    new_crashdump['METADATA'][fw] = fw_info[fw]
                # log ： log is one of the records from RegRawData.json.
                new_crashdump['METADATA']['timestamp'] = log.get("Get Cpu Register Time", None)
                new_crashdump['METADATA']['trigger_type'] = log.get("Mca Trigger Type", None)

                for socket in sockets:  # sockets ： List of CPUs
                    skt_string = 'socket%d' % socket
                    new_crashdump['METADATA']['cpu%d' % socket] = OrderedDict()
                    new_crashdump['METADATA']['cpu%d' % socket]['core_count'] = cpu_info[socket]['core_count']
                    new_crashdump['METADATA']['cpu%d' % socket]['cpuid'] = cpu_info[socket]['cpuid']
                    new_crashdump['METADATA']['cpu%d' % socket]['mca_err_src_log'] = log.get("Csr Register Data", None)[0].get("Cpu%d_MCA_ERR_SRC_LOG" % socket, 'N/A')
                    # print(log.get("Csr Register Data", None)[0].get("Cpu%d_MCA_ERR_SRC_LOG" % socket, None))
                    firstierrtsclo = log.get("Csr Register Data", None)[0].get("Cpu%d_PCU_FIRST_IERR_TSC_LO" % socket, 'N/A')
                    firstierrtschi = log.get("Csr Register Data", None)[0].get("Cpu%d_PCU_FIRST_IERR_TSC_HI" % socket, 'N/A')

                    if firstierrtsclo and firstierrtschi and "N/A" != firstierrtsclo and "N/A" != firstierrtschi:
                        new_crashdump['METADATA']['cpu%d' % socket]['firstierrtsc'] = firstierrtschi + firstierrtsclo[2:]
                    firstmcerrtsclo = log.get("Csr Register Data", None)[0].get("Cpu%d_PCU_FIRST_MCERR_TSC_LO" % socket, 'N/A')
                    firstmcerrtschi = log.get("Csr Register Data", None)[0].get("Cpu%d_PCU_FIRST_MCERR_TSC_HI" % socket, 'N/A')
                    if firstmcerrtsclo and firstmcerrtschi and "N/A" != firstmcerrtsclo and "N/A" != firstmcerrtschi:
                        new_crashdump['METADATA']['cpu%d' % socket]['firstmcerrtsc'] = firstmcerrtschi + firstmcerrtsclo[2:]
                    new_crashdump['METADATA']['cpu%d' % socket]['ierrloggingreg'] = log.get("Csr Register Data", None)[0].get("Cpu%d_IERRLOGGING" % socket, 'N/A')
                    new_crashdump['METADATA']['cpu%d' % socket]['mcerrloggingreg'] = log.get("Csr Register Data", None)[0].get("Cpu%d_MCERRLOGGING" % socket, 'N/A')
                    new_crashdump['METADATA']['cpu%d' % socket]['package_id'] = "N/A"
                    new_crashdump['METADATA']['cpu%d' % socket]['peci_id'] = "N/A"
                    new_crashdump['METADATA']['cpu%d' % socket]['ppin'] = cpu_info[socket]['ppin']
                    new_crashdump['METADATA']['cpu%d' % socket]['ucode_patch_ver'] = "N/A"
                new_crashdump['PROCESSORS']['_version'] = '0x0f0' + ver_id

                for socket in sockets:
                    new_crashdump['PROCESSORS']['cpu%d' % socket] = OrderedDict()
                    new_crashdump['PROCESSORS']['cpu%d' % socket]['MCA'] = OrderedDict()
                    new_crashdump['PROCESSORS']['cpu%d' % socket]['MCA']['_version'] = '0x3e0' + ver_id
                    new_crashdump['PROCESSORS']['cpu%d' % socket]['uncore'] = OrderedDict()
                    new_crashdump['PROCESSORS']['cpu%d' % socket]['uncore']['_version'] = '0x080' + ver_id

                csr_data = log.get("Csr Register Data", None)  # csr_date is a list
                ret_dict = deal_regrawdata_csr(new_crashdump['PROCESSORS'], csr_data, cpu_type)
                mca_data = log.get("Msr Register Data", None)  # mca_data is a list
                ret_dict = deal_regrawdata_mca(ret_dict, mca_data)
                cha_data = log.get("Raw CHA Register Data", None)
                ret_dict = deal_regrawdata_cha(ret_dict, cha_data)
                for crashdump in all_list:
                    if crashdump["METADATA"]["trigger_type"] == "BMC(PECI)" and crashdump["METADATA"]["timestamp"] == new_crashdump['METADATA']['timestamp']:
                        new_crashdump['METADATA']['CollectIntegrity'] = 1
                        new_crashdump['PROCESSORS'] = merge_dic(new_crashdump['PROCESSORS'], crashdump['PROCESSORS'])
                make_file(rawdata_filename, new_crashdump, i)
                i = i + 1
    except Exception as e:
        error_list.append((rawdata_filename, str(e)))
    return error_list

# according to the input ret_dict and cha_data(cha_data is the "Raw CHA Register Data" in log),
# return the updated ret_dict.
def deal_regrawdata_cha(ret_dict, cha_data):
    if cha_data:
        for cha in cha_data:
            for key in cha:
                ret_dict = update_cha_dict(ret_dict, key, cha[key])
    return ret_dict

# according to the input cha_dict、key and val,
# return the updated cha_dict.
def update_cha_dict(cha_dict, key, val):
    key = key.lower()
    val = val.lower().replace("Errcode:", "CC:")
    names = re.search("(cpu.*)_cha(.*)_mc[\d]{1,3}_(.*)", key, re.M | re.I)
    if names:
        if cha_dict.get(names.group(1), None) == None:
            cha_dict[names.group(1)] = {}
        if cha_dict[names.group(1)].get('MCA', None) == None:
            cha_dict[names.group(1)]['MCA'] = {}
        if cha_dict[names.group(1)]['MCA'].get("uncore", None) == None:
            cha_dict[names.group(1)]['MCA']['uncore'] = {}
        if cha_dict[names.group(1)]['MCA']['uncore'].get("CBO" + names.group(2)) == None:
            cha_dict[names.group(1)]['MCA']['uncore']["CBO" + names.group(2)] = {}
        cha_dict[names.group(1)]['MCA']['uncore']["CBO" + names.group(2)]["cbo" + names.group(2) +"_"+names.group(3)] = val
    return cha_dict

# according to the input ret_dict and mca_data(mca_data is the "Msr Register Data" in log),
# return the updated ret_dict.
def deal_regrawdata_mca(ret_dict, mca_data):              # mca_data is a list
    if mca_data:
        for mca in mca_data:
            for key in mca:
                ret_dict = update_mca_dict(ret_dict, key, mca[key])
    return ret_dict

# according to the input mca_dict、key and val,
# return the updated mca_dict.
def update_mca_dict(mca_dict, key, val):
    key = key.lower()
    val = val.lower().replace("Errcode:", "CC:")
    if 'thread' not in key:
        names = re.search("(cpu[0-9])_(core[0-9]{1,2})_(.*)", key, re.M | re.I)
        if names:
            name = re.search("(mc[0-9]{1,2})(.*)", names.group(3), re.M | re.I)
            if name:
                if mca_dict.get(names.group(1), None) == None:
                    mca_dict[names.group(1)] = {}
                if mca_dict[names.group(1)].get('MCA', None) == None:
                    mca_dict[names.group(1)]['MCA'] = {}
                if int(name.group(1)[2:]) > 3:
                    if mca_dict[names.group(1)]['MCA'].get("uncore", None) == None:
                        mca_dict[names.group(1)]['MCA']['uncore'] = {}
                    if mca_dict[names.group(1)]['MCA']['uncore'].get(name.group(1).upper(), None) == None:
                        mca_dict[names.group(1)]['MCA']['uncore'][name.group(1).upper()] = {}
                    mca_dict[names.group(1)]['MCA']['uncore'][name.group(1).upper()][
                        name.group(1) + '_' + name.group(2)] = val
                else:
                    if mca_dict[names.group(1)]['MCA'].get(names.group(2), None) == None:
                        mca_dict[names.group(1)]['MCA'][names.group(2)] = {}
                    if mca_dict[names.group(1)]['MCA'][names.group(2)].get("thread0", None) == None:
                        mca_dict[names.group(1)]['MCA'][names.group(2)]["thread0"] = {}
                    if mca_dict[names.group(1)]['MCA'][names.group(2)]["thread0"].get(name.group(1).upper(), None) == None:
                        mca_dict[names.group(1)]['MCA'][names.group(2)]["thread0"][name.group(1).upper()] = {}
                    mca_dict[names.group(1)]['MCA'][names.group(2)]["thread0"][name.group(1).upper()][name.group(1) + '_' + name.group(2)] = val
    else:
        names = re.search("(cpu[0-9]{1,2})_(core[0-9]{1,2})_(thread[0-9])_(.*)", key, re.M | re.I)
        if names:
            name = re.search("(mc[0-9]{1,2})(.*)", names.group(4), re.M | re.I)
            if name:
                if mca_dict.get(names.group(1), None) == None:
                    mca_dict[names.group(1)] = {}
                if mca_dict[names.group(1)].get('MCA', None) == None:
                    mca_dict[names.group(1)]['MCA'] = {}
                if mca_dict[names.group(1)]['MCA'].get(names.group(2), None) == None:
                    mca_dict[names.group(1)]['MCA'][names.group(2)] = {}
                if mca_dict[names.group(1)]['MCA'][names.group(2)].get(names.group(3), None) == None:
                    mca_dict[names.group(1)]['MCA'][names.group(2)][names.group(3)] = {}
                if mca_dict[names.group(1)]['MCA'][names.group(2)][names.group(3)].get(name.group(1).upper(),None) == None:
                    mca_dict[names.group(1)]['MCA'][names.group(2)][names.group(3)][name.group(1).upper()] = {}
                mca_dict[names.group(1)]['MCA'][names.group(2)][names.group(3)][name.group(1).upper()][
                    name.group(1) + '_' + name.group(2)] = val
    return mca_dict


# according to the input ret_dict、csr_data and cpu_type(csr_data is the "Csr Register Data" in log),
# return the updated ret_dict.
def deal_regrawdata_csr(ret_dict, csr_data, cpu_type):    # csr_date is a list
    if csr_data:
        for csr in csr_data:
            for key in csr:
                ret_dict = update_csr_dict(ret_dict, key, csr[key], cpu_type)
    return ret_dict

# according to the input csr_dict、key_str、val and cpu_type,
# return the updated mca_dict.
def update_csr_dict(csr_dict, key_str, val, cpu_type):
    val = val.replace("Errcode:", "CC:")
    reg_map = get_inspur_reg_map(cpu_type)
    name = re.match('(cpu[0-9]{1,2})_(.*)', key_str, re.M | re.I)
    if name:
        cpu_name = name.group(1).lower()
        csrlist = name.group(2).split('_')
        if csr_dict.get(cpu_name, None) == None:
            csr_dict[cpu_name] = {}
            csr_dict[cpu_name]['uncore'] = {}
        found_flag = False
        for reg in reg_map:
            if (len(csrlist) >= len(reg[5].split("_"))) and ("_".join(csrlist[(len(csrlist) - len(reg[5].split("_"))):]) == reg[5].strip()):
                temp = re.match('rootport([0-9])', key_str.lower(), re.M | re.I)
                if temp:
                    num = 1 + temp.group(1)
                    bus = "0" + num
                else:
                    if reg[0].strip() == "13":
                        bus = "30"
                    elif reg[0].strip() == "14":
                        bus = "31"
                    elif reg[0].strip() == "ROOT_BUS0":
                        bus = "00"
                    elif reg[0].strip() == "ROOT_BUS1":
                        bus = "01"
                    elif reg[0].strip() == "ROOT_BUS_ALL":
                        bus = "0"+csrlist[0][-1]
                    else:
                        bus = '0'+reg[0].strip()
                if int(reg[1].strip()) < 10:
                    dev = '0'+reg[1].strip()
                else:
                    dev = reg[1].strip()
                csr_dict[cpu_name]['uncore']["B"+bus+"_"+"D"+dev+"_"+"F"+hex(int(reg[2].strip(),16))[2:]+"_0x"+hex(int(reg[3].strip(),16))[2:].upper()] = val
                found_flag = True
                break
        if not found_flag:
            #logger = logger_cof("onekeylog.log")
            write_log("ERROR: unknown register %s. Need to update %sinspurrawreg.txt" % (name.group(2), cpu_type))
            # print("ERROR: unknown register %s. Need to update %sinspurrawreg.txt" % (name.group(2), cpu_type))
    return csr_dict





