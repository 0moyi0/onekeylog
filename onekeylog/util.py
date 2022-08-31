# -><- coding: utf-8 -*-
# 23/07/2022
import logging
import json
import os
import re
from collections import OrderedDict
import cpx_opcode_def
import opcodes_def

# get the regular expression of the target section from the configuration.py,
# To regularize the TXT text, return a dict
def get_dict_by_conf(cof_file, target, txt):
    ret = {}
    conf_json, error_list = _read_json(cof_file)
    conf_json = conf_json[target]
    for dict in conf_json:
        for key in dict.keys():
            ret[key] = None
            temp = re.search(dict[key], txt, re.M | re.I)
            if temp:
                ret[key] = temp.group(1)
    return  ret

# If the regular expression for the 'bank_id' field in Configuration.py does not
# obtain the correct value, print the "bank_id" field in the errorAnalyreport.json file.
def deal_bankid_None(file, target):
    list = get_file_list(file)
    for i in list:
        mat = re.search(target, i, re.M | re.I)
        if mat:
            #logger = logger_cof("onekeylog.log")
            write_log("WARNING: No bank id. %s" % i)
            # print("WARNING: No bank id. %s" % i)
            return True
    return False

# If the file_name is a string, the contents of the file are read by line with
# newlines and whitespace removed and stored in the list.
# if file_name is a dict,the dict is converted to a string, Remove newlines,
# whitespace from that, in finally,cut into a list based on commas
# if the other type， print the error info and return a empty list(just []).
def get_file_list(filename = None):
    if not logger:
        init_logger()
    list = []
    if isinstance(filename, str):
        if os.path.exists(filename):
            with open(filename, "r") as regname:
                reglist = regname.readlines()
                for line in reglist:
                    list.append(line.replace("\\n","").replace("\t","").replace("\"","").replace("'","").replace("\\","").strip())
    elif isinstance(filename, dict):
        txt = str(filename).replace("\t","").replace("\"","").replace("'","").replace("\\","").replace("\\n","")#.replace(" ", "")
        list = txt.split(',')
    else:
        #logger = logger_cof("onekeylog.log")
        write_log("{} no find".format(type(filename)))
        # print("{} no find".format(type(filename)))
        return None
    return list

# read filename's data and return data of json
def _read_json(filename=None):
    error_list = []
    json_object = None
    try:
        crashfile = open(filename, 'r')
        json_object = json.load(crashfile)
        crashfile.close()
    except Exception as e:
        json_object = None
        error_list.append((filename,str(e)))
    return json_object, error_list


# according to the input new_crashdump data,
# generate the corresponding  converted_filename_i.json file.
# @parameter - filename： the file_name to prepare for generation.
# @parameter - new_crashdump： Dict data to be written to the file.
# @parameter - i： the index number of the generated file.
# return - None
def make_file(filename, new_crashdump, i):
    if not logger:
        init_logger()
    new_filename = 'converted_%s_%i%s' % (os.path.basename(filename).replace("ErrorAnalyReport.json", "RegAnalyRpt").replace(".json", ""), i,".json")  # TODO
    dest_folder = os.path.abspath(os.path.dirname(filename))  # os.path.abspath()
    full_path = os.path.join(dest_folder, new_filename)
    #logger = logger_cof("onekeylog.log")
    write_log("Converted json is located at: %s" % full_path)
    # print("Converted json is located at: %s" % full_path)
    file_handle = open(full_path, 'w')
    json.dump(new_crashdump, file_handle, indent=4)
    file_handle.close()

# If the file_name is a string, the contents of the file are read line by line to
# remove whitespace and concatenate the contents of all lines into a string.
# If it is a dict, the dict is converted to a string, then remove the white space
# and newline characters, return string.
# if the other type， print the error info and return a empty string(just "").
def get_file_retxt(filename = None):
    if not logger:
        init_logger()
    txt = ""
    if isinstance(filename, str):
        if os.path.exists(filename):
            with open(filename, "r") as regname:
                reglist = regname.readlines()
            for line in reglist:
                txt = txt + line.replace("\\n","").replace("\t","").replace("\"","").replace("'","").replace("\\","")#.replace(" ", "")
    elif isinstance(filename, dict):
        txt = str(filename).replace("\t","").replace("\"","").replace("'","").replace("\\","").replace("\\n","")#.replace(" ", "")
    else:
        #logger = logger_cof("onekeylog.log")
        write_log("{} no find".format(type(filename)))
        # print("{} no find".format(type(filename)))
        return None
    return txt

SAD_RESULT = {
    'HOM': 0,
    'MMIO': 1,
    'CFG': 2,
    'MMIO Partial Read': 3,
    'IO': 4,
    'Intel Reserved': 5,
    'SPC': 6,
    'Intel Reserved': 7
}

def covert_icx_tor_dump(tor_info, tordump0, tordump1, tordump2):
    if not logger:
        init_logger()
    torkey_list = list(tor_info.keys())
    if "CPU" in torkey_list and "CHA" in torkey_list and "TOR" in torkey_list:
        torkey_list.remove("CPU")
        torkey_list.remove("CHA")
        torkey_list.remove("TOR")
    else:
        return False
    for tor_key in torkey_list:
        if "Valid" == tor_key:
            tordump0[0] = tordump0[0] | (tor_info["Valid"] << 2)
        elif "Retry" == tor_key:
            tordump0[0] = tordump0[0] | (tor_info["Retry"] << 5)
        elif "InPipe" == tor_key:
            tordump0[0] = tordump0[0] | (tor_info["InPipe"] << 7)
        elif "Thread" == tor_key:
            tordump0[1] = (tor_info["Thread"] & 0x7) << 8
        elif "SadResult" == tor_key:
            tordump0[2] = tordump0[2] | ((SAD_RESULT[tor_info["SadResult"]]) & 0x7) << 18
        elif "Target" == tor_key:
            tor_info["Target"] = tor_info["Target"].replace("UPI", "KTI")
            tordump0[2] = tordump0[2] | (
                        (opcodes_def.inverseDict(opcodes_def.TARGET_LOC_PORT_BY_VAL)[tor_info["Target"]]) & 0x1f) << 7
        elif "Core" == tor_key:
            id = 0
            if tor_info["Core"].lower().startswith("core"):
                id = int(tor_info["Core"][4:])
            elif tor_info["Core"].lower().startswith("upi"):  # TODO "UPI" ?
                if int(tor_info["Core"][3:]) >= 3:
                    write_log("ERROR: Unknown Core value %s" % tor_info["Core"])
                    raise Exception("ERROR: Unknown Core value %s"%tor_info["Core"])
                else:
                    id = int(tor_info["Core"][3:]) + 54
            elif tor_info["Core"].lower().startswith("pcie"):  # TODO "IIO" or "PCIE"?
                if int(tor_info["Core"][4:]) >= 6:
                    write_log("ERROR: Unknown Core value %s" % tor_info["Core"])
                    raise Exception("ERROR: Unknown Core value %s"%tor_info["Core"])
                else:
                    id = (~(int(tor_info["Core"][4:]) & 0x3) & 0x3) + 60
            else:
                # = logger_cof("onekeylog.log")
                write_log("ERROR: Unknown Core value %s"%tor_info["Core"])
                # print("ERROR: Unknown Core value %s"%tor_info["Core"])
                raise Exception("ERROR: Unknown Core value %s"%tor_info["Core"])
            tordump0[3] = tordump0[3] | (id & 0x3f) << 21
        elif "OpCode" == tor_key:
            try:
                tordump0[4] = tordump0[4] | (int(tor_info["OpCode"], 16) & 0x7ff) << 17
            except:
                opcode = tor_info["OpCode"].strip()
                if opcode == "PerfData":
                    opcode = "PrefData"
                elif opcode == "RdData":
                    opcode = "KRdData"
                tordump0[4] = tordump0[4] | (opcodes_def.TOR_OPCODES[opcode] & 0x7ff) << 17
        elif "CacheState" == tor_key:
            try:
                tordump0[7] = tordump0[7] | (int(tor_info["CacheState"], 16) & 0xf) << 3
            except:
                tordump0[7] = tordump0[7] | (opcodes_def.CACHE_STATE[tor_info["CacheState"]] & 0xf) << 3
        elif "SystemAddress" == tor_key or "SystemAddres" == tor_key:
            addr = int(tor_info[tor_key].split(" ")[0], 16)
            tordump1[0] = tordump1[0] | (addr & 0x01c0) << (29 - 6)
            tordump1[1] = tordump1[1] | (addr & 0x0E0000) << (29 - 17)
            tordump1[2] = tordump1[2] | (addr & 0x070000000) << (29 - 28)
            tordump1[3] = tordump1[3] | (addr & 0x038000000000) >> (39 - 29)
            tordump1[4] = tordump1[4] | (addr & 0x0c000000000000) >> (50 - 29)
            tordump2[0] = tordump2[0] | (addr & 0x1fe00) >> 9
            tordump2[1] = tordump2[1] | (addr & 0x0ff00000) >> 20
            tordump2[2] = tordump2[2] | (addr & 0x07f80000000) >> 31
            tordump2[3] = tordump2[3] | (addr & 0x03fc0000000000) >> 42
        elif "Fsm" == tor_key:
            if isinstance(tor_info["Fsm"], str):
                try:
                    tordump1[7] = tordump1[7] | (int(tor_info["Fsm"], 16) & 0x1f) << 1
                except:
                    tordump1[7] = tordump1[7] | (opcodes_def.ISMQ_FSM[tor_info["Fsm"]] & 0x1f) << 1
            elif isinstance(tor_info["Fsm"], int):
                tordump1[7] = tordump1[7] | (tor_info["Fsm"] & 0x1f) << 1
        else:
            print("ERROR: Unknown tor key %s" % tor_key)
            # = logger_cof("onekeylog.log")
            write_log("ERROR: Unknown tor key %s" % tor_key)
            # print("ERROR: Unknown tor key %s" % tor_key)
    return True

def covert_cpx_tor_dump(tor_info, dw):
    if not logger:
        init_logger()
    torkey_list = list(tor_info.keys())
    if "CPU" in torkey_list and "CHA" in torkey_list:
        torkey_list.remove("CPU")
        torkey_list.remove("CHA")
    else:
        return False
    for tor_key in torkey_list:
        if isinstance(tor_info[tor_key], str):
            tor_info[tor_key] = tor_info[tor_key].strip()
        if "Valid" == tor_key:
            dw[0] = dw[0] | (tor_info["Valid"] << 1 | tor_info["Valid"])
        elif "Retry" == tor_key:
            dw[0] = dw[0] | (tor_info["Retry"] << 2)
        elif "InPipe" == tor_key:
            dw[0] = dw[0] | (tor_info["InPipe"] << 3)
        elif "TOR" == tor_key:
            dw[0] = (tor_info["TOR"] & 0x1F) << 9
        elif "SadResult" == tor_key:
            dw[1] = dw[1] | ((cpx_opcode_def.Sad_Result_Decoding[tor_info["SadResult"]]) & 0x7) << 25
        elif "Target" == tor_key:
            tor_info["Target"] = tor_info["Target"].replace("UPI", "KTI")
            try:
                dw[1] = dw[1] | (int(tor_info["Target"], 16) & 0x1f) << 20
            except:
                dw[1] = dw[1] | (
                        (cpx_opcode_def.Targeted_Port_Decoding[tor_info["Target"]]) & 0x1f) << 20
        elif "Core" == tor_key:
            core = tor_info["Core"].strip()
            if core == "KTI0\/1":
                core = "KTI0/1"
            if core == "KTI2\/3":
                core = "KTI2/3"
            if core == "KTI4\/5":
                core = "KTI4/5"
            core = core.lower()
            if core.startswith("core"):
                id = int(core[4:])
            else:
                id = cpx_opcode_def.CoreId_decoding[core.upper()]
            dw[0] = dw[0] | (id & 0x3f) << 14
        elif "Thread" == tor_key:
            dw[0] = dw[0] | (tor_info["Thread"] & 0x1) << 20
        elif "OpCode" == tor_key:
            try:
                dw[0] = dw[0] | (int(tor_info["OpCode"], 16) & 0x7ff) << 21
            except:
                opcode = tor_info["OpCode"].strip()
                if opcode == "PerfData":
                    opcode = "PrefData"
                elif opcode == "RdData":
                    opcode = "KRdData"
                elif opcode == "Interrupt Priority Update":
                    opcode = "IntPriUp"
                dw[0] = dw[0] | (cpx_opcode_def.TOR_OPCODES[opcode] & 0x7ff) << 21
        elif "CacheState" == tor_key:
            try:
                dw[1] = dw[1] | (int(tor_info["CacheState"], 16) & 0xf) << 28
            except:
                dw[1] = dw[1] | (cpx_opcode_def.CatchState_Decoding[tor_info["CacheState"]] & 0xf) << 28
        elif "SystemAddres" == tor_key or "SystemAddress" == tor_key:
            addr = int(tor_info[tor_key].split(" ")[0], 16)
            dw[1] = dw[1] | (addr & 0x3FFF)
            dw[2] = dw[2] | (addr >> 14)

        elif "Fsm" == tor_key:
            if isinstance(tor_info["Fsm"], str):
                try:
                    dw[1] = dw[1] | (int(tor_info["Fsm"], 16) & 0x3f) << 14
                except:
                    # = logger_cof("onekeylog.log")
                    write_log("ERROR: Unknown FSM State %s"%tor_info["Fsm"])
                    # print("ERROR: Unknown FSM State %s"%tor_info["Fsm"])
            elif isinstance(tor_info["Fsm"], int):
                dw[1] = dw[1] | (tor_info["Fsm"] & 0x3f) << 14
        else:
            # = logger_cof("onekeylog.log")
            write_log("ERROR: Unknown tor key %s" % tor_key)
            # print("ERROR: Unknown tor key %s" % tor_key)
    return True

# according to the input CPU type is ICX's Errorlist, return tor_data.
def get_report_icx_TOR_dump(Errorlist):
    if not logger:
        init_logger()
    tor_data = {}
    for error in Errorlist:
        if error.get("ErrorArch", None) == "TorDump":
            tor_info_list = error.get("TorDump Info", None)
            for tor_info in tor_info_list:
                tordump0 = [0, 0, 0, 0, 0, 0, 0, 0]
                tordump1 = [0, 0, 0, 0, 0, 0, 0, 0]
                tordump2 = [0, 0, 0, 0, 0, 0, 0, 0]
                if covert_icx_tor_dump(tor_info, tordump0, tordump1, tordump2):
                    if tor_info["CPU"] not in tor_data.keys():
                        tor_data[tor_info["CPU"]] = OrderedDict()
                    if "cha" + str(tor_info["CHA"]) not in tor_data[tor_info["CPU"]].keys():
                        tor_data[tor_info["CPU"]]["cha" + str(tor_info["CHA"])] = OrderedDict()
                    tor_data[tor_info["CPU"]]["cha" + str(tor_info["CHA"])][
                        "index" + str(tor_info["TOR"])] = OrderedDict()
                    for i in range(8):
                        tor_data[tor_info["CPU"]]["cha" + str(tor_info["CHA"])]["index" + str(tor_info["TOR"])][
                            "subindex" + str(i)] = hex(tordump2[i] << 64 | tordump1[i] << 32 | tordump0[i])
                else:
                    # = logger_cof("onekeylog.log")
                    write_log("ERROR: tor dump decode failed\n", tor_info)
                    # print("ERROR: tor dump decode failed\n", tor_info)
    return tor_data

# according to the input CPU type is CPX's Errorlist, return tor_data.
def get_report_cpx_TOR_dump(Errorlist):
    if not logger:
        init_logger()
    tor_data = {}
    for error in Errorlist:
        if error.get("ErrorArch", None) == "TorDump":
            tor_info_list = error.get("TorDump Info", None)
            for tor_info in tor_info_list:
                DW = [0,0,0]
                if covert_cpx_tor_dump(tor_info, DW):
                    if tor_info["CPU"] not in tor_data.keys():
                        tor_data[tor_info["CPU"]] = OrderedDict()
                    if "cha" + str(tor_info["CHA"]) not in tor_data[tor_info["CPU"]].keys():
                        tor_data[tor_info["CPU"]]["cha" + str(tor_info["CHA"])] = OrderedDict()
                    tor_data[tor_info["CPU"]]["cha" + str(tor_info["CHA"])][
                        "index" + str(tor_info["TOR"])] = OrderedDict()
                    for i in range(3):
                        tor_data[tor_info["CPU"]]["cha" + str(tor_info["CHA"])]["index" + str(tor_info["TOR"])][
                            "subindex" + str(i)] = hex(DW[i])
                else:
                    # = logger_cof("onekeylog.log")
                    write_log("ERROR: tor dump decode failed\n", tor_info)
                    # print("ERROR: tor dump decode failed\n", tor_info)
    return tor_data


# get RESTful version info from compoent.log
def get_component_fw_info(log_name):
    txt = get_file_retxt(log_name)
    ret_info = get_dict_by_conf("configuration.py", "fw_info", txt)
    return ret_info

# reset the val in the dict_a, except '_version'.
def reset_dic(dict_a):
    for key in dict_a.keys():
        if isinstance(dict_a[key], dict):           # isinstance()  对象的类型与参数二的类型相同返回true，否则false
            reset_dic(dict_a[key])
        else:
            if key != '_version':
                dict_a[key] = "N/A"

imc_chn_map = {
    "0x0": ["10", "3"],
    "0x1": ["10", "7"],
    "0x2": ["11", "3"],
    "0x3": ["12", "3"],
    "0x4": ["12", "7"],
    "0x5": ["13", "3"]
}
cpx_reg_map = {
    "MSR_MCG_CONTAIN": "cpu%c/uncore/RDIAMSR_0x178",
    "IA32_MCG_STATUS": "cpu%c/uncore/RDIAMSR_0x17A",
    "IA32_MCG_CAP": "cpu%c/uncore/RDIAMSR_0x179",
    "MCA_ERROR_CONTROL": "cpu%c/uncore/RDIAMSR_0x17F",
    "IA32_MCi_CTL": "cpu%c/MCA/uncore/MC%b/mc%b_ctl",
    "IA32_MCi_CTL2": "cpu%c/MCA/uncore/MC%b/mc%b_ctl2",
    "IA32_MCi_STATUS": "cpu%c/MCA/uncore/MC%b/mc%b_status",
    "IA32_MCi_ADDR": "cpu%c/MCA/uncore/MC%b/mc%b_addr",
    "IA32_MCi_MISC": "cpu%c/MCA/uncore/MC%b/mc%b_misc",
    "IA32_MCc_CTL": "cpu%c/MCA/uncore/CBO%n/cbo%n_ctl",
    "IA32_MCc_CTL2": "cpu%c/MCA/uncore/CBO%n/cbo%n_ctl2",
    "IA32_MCc_STATUS": "cpu%c/MCA/uncore/CBO%n/cbo%n_status",
    "IA32_MCc_ADDR": "cpu%c/MCA/uncore/CBO%n/cbo%n_addr",
    "IA32_MCc_MISC": "cpu%c/MCA/uncore/CBO%n/cbo%n_misc",
    "IA32_MCx_CTL": "cpu%c/MCA/core%d/thread0/MC%b/mc%b_ctl",
    "IA32_MCx_CTL2": "cpu%c/MCA/core%d/thread0/MC%b/mc%b_ctl2",
    "IA32_MCx_STATUS": "cpu%c/MCA/core%d/thread0/MC%b/mc%b_status",
    "IA32_MCx_ADDR": "cpu%c/MCA/core%d/thread0/MC%b/mc%b_addr",
    "IA32_MCx_MISC": "cpu%c/MCA/core%d/thread0/MC%b/mc%b_misc",
    "THREAD_SMI_ERR_SRC": "cpu%c/core%d/thread0/RDIAMSR_0x158",
    "CORE_SMI_ERR_SRC": "cpu%c/core%d/RDIAMSR_0x17C",
    "UNCORE_SMI_ERR_SRC": "cpu%c/uncore/RDIAMSR_0x17E",
    "IerrLoggingReg": "cpu%c/uncore/B00_D08_F0_0xA4",
    "McerrLoggingReg": "cpu%c/uncore/B00_D08_F0_0xA8",
    "EMCA_CORE_CSMI_LOG": "cpu%c/uncore/B00_D08_F0_0xB0",
    "EMCA_CORE_CSMI_LOG1": "cpu%c/uncore/B00_D08_F0_0xB4",
    "EMCA_CORE_MSMI_LOG": "cpu%c/uncore/B00_D08_F0_0xB8",
    "EMCA_CORE_MSMI_LOG1": "cpu%c/uncore/B00_D08_F0_0xBC",
    "MCA_ERR_SRC_LOG": "cpu%c/uncore/B01_D30_F2_0xEC",

    "RETRY_RD_CH_NUM": "0",
    "RETRY_RD_ERR_LOG": "cpu%c/uncore/B02_D%e_F%f_0x154",
    "RETRY_RD_ERR_LOG_MISC": "cpu%c/uncore/B02_D%e_F%f_0x148",
    "RETRY_RD_ERR_LOG_PARITY": "cpu%c/uncore/B02_D%e_F%f_0x150",
    "RETRY_RD_ERR_LOG_ADDRESS1": "cpu%c/uncore/B02_D%e_F%f_0x15C",
    "RETRY_RD_ERR_LOG_ADDRESS2": "cpu%c/uncore/B02_D%e_F%f_0x114",
    "Correrrorstatus": "cpu%c/uncore/B02_D%e_F%f_0x134",
    "RETRY_RD_ERR_LOG_ADDRESS3N0": None,
    "RETRY_RD_ERR_LOG_ADDRESS3N1": None,

    "PCU_FIRST_IERR_TSC_LO": "cpu%c/uncore/B01_D30_F4_0xF0",
    "PCU_FIRST_IERR_TSC_HI": "cpu%c/uncore/B01_D30_F4_0xF4",
    "PCU_FIRST_MCERR_TSC_LO": "cpu%c/uncore/B01_D30_F4_0xF8",
    "PCU_FIRST_MCERR_TSC_HI": "cpu%c/uncore/B01_D30_F4_0xFC",

    "UNCORE_FIVR_ERR_LOG": "cpu%c/uncore/B01_D30_F2_0x84",
    "CORE_FIVR_ERR_LOG_0": "cpu%c/uncore/B31_D30_F2_0x80",
    "CORE_FIVR_ERR_LOG_1": None
}

# icx_reg_map
icx_reg_map = {
    "MSR_MCG_CONTAIN":      ["cpu%c/uncore/RDIAMSR_0x178"],
    "IA32_MCG_STATUS":      ["cpu%c/uncore/RDIAMSR_0x17A"],
    "IA32_MCG_CAP":         ["cpu%c/uncore/RDIAMSR_0x179"],
    "MCA_ERROR_CONTROL":    ["cpu%c/uncore/RDIAMSR_0x17F"],
    "IA32_MCi_CTL":         ["cpu%c/MCA/uncore/MC%b/mc%b_ctl"],
    "IA32_MCi_CTL2":        ["cpu%c/MCA/uncore/MC%b/mc%b_ctl2"],
    "IA32_MCi_STATUS":      ["cpu%c/MCA/uncore/MC%b/mc%b_status"],
    "IA32_MCi_ADDR":        ["cpu%c/MCA/uncore/MC%b/mc%b_addr"],
    "IA32_MCi_MISC":        ["cpu%c/MCA/uncore/MC%b/mc%b_misc"],
    "IA32_MCc_CTL":         ["cpu%c/MCA/uncore/CBO%n/cbo%n_ctl"],
    "IA32_MCc_CTL2":        ["cpu%c/MCA/uncore/CBO%n/cbo%n_ctl2"],
    "IA32_MCc_STATUS":      ["cpu%c/MCA/uncore/CBO%n/cbo%n_status"],
    "IA32_MCc_ADDR":        ["cpu%c/MCA/uncore/CBO%n/cbo%n_addr"],
    "IA32_MCc_MISC":        ["cpu%c/MCA/uncore/CBO%n/cbo%n_misc"],
    "IA32_MCx_CTL":         ["cpu%c/MCA/core%d/thread%t/MC%b/mc%b_ctl"],
    "IA32_MCx_CTL2":        ["cpu%c/MCA/core%d/thread%t/MC%b/mc%b_ctl2"],
    "IA32_MCx_STATUS":      ["cpu%c/MCA/core%d/thread%t/MC%b/mc%b_status"],
    "IA32_MCx_ADDR":        ["cpu%c/MCA/core%d/thread%t/MC%b/mc%b_addr"],
    "IA32_MCx_MISC":        ["cpu%c/MCA/core%d/thread%t/MC%b/mc%b_misc"],
    "THREAD_SMI_ERR_SRC":   ["cpu%c/core%d/thread%t/RDIAMSR_0x158"],
    "CORE_SMI_ERR_SRC":     ["cpu%c/core%d/RDIAMSR_0x17C"],
    "UNCORE_SMI_ERR_SRC":   ["cpu%c/uncore/RDIAMSR_0x17E"],
    "IerrLoggingReg":       ["cpu%c/uncore/B30_D00_F0_0xA4"],
    "McerrLoggingReg":      ["cpu%c/uncore/B30_D00_F0_0xA8"],
    "EMCA_CORE_CSMI_LOG":   ["cpu%c/uncore/B30_D00_F0_0xB0"],
    "EMCA_CORE_CSMI_LOG1":  ["cpu%c/uncore/B30_D00_F0_0xB4"],
    "EMCA_CORE_MSMI_LOG":   ["cpu%c/uncore/B30_D00_F0_0xB8"],
    "EMCA_CORE_MSMI_LOG1":  ["cpu%c/uncore/B30_D00_F0_0xBC"],
    "MCA_ERR_SRC_LOG":      ["cpu%c/uncore/B31_D30_F2_0xEC"],
    "RETRY_RD_CH_NUM":      [0,0x4000],
    "RETRY_RD_SET2_CH_NUM": [0,0x4000],
    "RETRY_RD_ERR_LOG":             ["cpu%c/uncore/B30_D00_F1_%o", 0x22C60],
    "RETRY_RD_ERR_LOG_MISC":        ["cpu%c/uncore/B30_D00_F1_%o", 0x22C54],
    "RETRY_RD_ERR_LOG_PARITY":      ["cpu%c/uncore/B30_D00_F1_%o", 0x22C5C],
    "RETRY_RD_ERR_LOG_ADDRESS1":    ["cpu%c/uncore/B30_D00_F1_%o", 0x22C58],
    "RETRY_RD_ERR_LOG_ADDRESS2":    ["cpu%c/uncore/B30_D00_F1_%o", 0x22C28],
    "RETRY_RD_ERR_LOG_ADDRESS3N0":  ["cpu%c/uncore/B30_D00_F1_%o", 0x20ED8],
    "RETRY_RD_ERR_LOG_ADDRESS3N1":  ["cpu%c/uncore/B30_D00_F1_%o", 0x20EDC],
    "RETRY_RD_ERR_SET2_LOG":        ["cpu%c/uncore/B30_D00_F1_%2o", 0x22E54],
    "RETRY_RD_ERR_SET2_LOG_MISC":   ["cpu%c/uncore/B30_D00_F1_%2o", 0x22E60],
    "RETRY_RD_ERR_SET2_LOG_PARITY": ["cpu%c/uncore/B30_D00_F1_%2o", 0x22E64],
    "RETRY_RD_ERR_SET2_LOG_ADDRESS1":   ["cpu%c/uncore/B30_D00_F1_%2o", 0x22E58],
    "RETRY_RD_ERR_SET2_LOG_ADDRESS2":   ["cpu%c/uncore/B30_D00_F1_%2o", 0x22E5C],
    "RETRY_RD_ERR_SET2_LOG_ADDRESS3N0": ["cpu%c/uncore/B30_D00_F1_%2o", 0x20EE0],
    "RETRY_RD_ERR_SET2_LOG_ADDRESS3N1": ["cpu%c/uncore/B30_D00_F1_%2o", 0x20EE4],
    "Correrrorstatus":                  ["cpu%c/uncore/B30_D00_F1_%o", 0x22C50],
    "PCU_FIRST_IERR_TSC_LO":            ["cpu%c/uncore/B31_D30_F4_0xF0"],
    "PCU_FIRST_IERR_TSC_HI":            ["cpu%c/uncore/B31_D30_F4_0xF4"],
    "PCU_FIRST_MCERR_TSC_LO":           ["cpu%c/uncore/B31_D30_F4_0xF8"],
    "PCU_FIRST_MCERR_TSC_HI":           ["cpu%c/uncore/B31_D30_F4_0xFC"],
    "UNCORE_FIVR_ERR_LOG":              ["cpu%c/uncore/B31_D30_F2_0x84"],
    "CORE_FIVR_ERR_LOG_0":              ["cpu%c/uncore/B31_D30_F2_0xC0"],
    "CORE_FIVR_ERR_LOG_1":              ["cpu%c/uncore/B31_D30_F2_0xC4"]
}

# according to the input key_list and value, generate a tree dict
def get_dic_key(key_list, value):
    if len(key_list) > 1:
        return {key_list[0]: get_dic_key(key_list[1:], value)}
    else:
        return {key_list[0]: value}

# CPU type is CPX's register name conversion mapping.
def cpx_reg_mapping(reg, value, cpuinfo):
    if not logger:
        init_logger()
    data_dic = {}
    if "IA32_MCi" in reg:
        if int(cpuinfo["bank_id"]) < 4:
            reg = reg.replace("MCi", "MCx")
        elif cpuinfo["cha_id"] is not None:
            reg = reg.replace("MCi", "MCc")
    if cpx_reg_map[reg]:
        if cpx_reg_map[reg] != "0":
            if '/' in cpx_reg_map[reg]:
                key_list = cpx_reg_map[reg].split("/")
                for i in range(0, len(key_list)):
                    if "%c" in key_list[i]:
                        key_list[i] = key_list[i].replace("%c", str(int(cpuinfo["socket_id"])))
                    elif "%d" in key_list[i]:
                        if cpuinfo["core_id"] == "uncore":
                            cpuinfo["core_id"] = "0"
                        key_list[i] = key_list[i].replace("%d", str(int(cpuinfo["core_id"])))
                    elif "%b" in key_list[i]:
                        key_list[i] = key_list[i].replace("%b", str(int(cpuinfo["bank_id"])))
                    elif "%n" in key_list[i]:
                        key_list[i] = key_list[i].replace("%n", str(int(cpuinfo["cha_id"])))
                    elif "%f" in key_list[i]:
                        key_list[i] = key_list[i].replace("%e", imc_chn_map[cpx_reg_map["RETRY_RD_CH_NUM"]][0])
                        key_list[i] = key_list[i].replace("%f", imc_chn_map[cpx_reg_map["RETRY_RD_CH_NUM"]][1])
                data_dic = get_dic_key(key_list, value)
        else:
            cpx_reg_map[reg] = hex(int(value, 16))
    else:
        print("WARNING: cpx_reg_map not found %s" %reg)
        write_log("WARNING: cpx_reg_map not found %s" %reg)
    return data_dic

# CPU type is ICX's register name conversion mapping.
def icx_reg_mapping(reg, value, cpuinfo):
    data_dic = {}
    if "IA32_MCi" in reg:
        if int(cpuinfo["bank_id"]) < 4:
            reg = reg.replace("MCi", "MCx")
        elif cpuinfo["cha_id"] is not None:
            reg = reg.replace("MCi", "MCc")
    if icx_reg_map[reg]:
        # print(reg, icx_reg_map[reg])
        if icx_reg_map[reg][0]:
            if '/' in icx_reg_map[reg][0]:
                key_list = icx_reg_map[reg][0].split("/")
                for i in range(0, len(key_list)):
                    if "%c" in key_list[i]:
                        key_list[i] = key_list[i].replace("%c", str(int(cpuinfo["socket_id"])))
                    elif "%d" in key_list[i]:
                        if cpuinfo["core_id"] == "uncore":
                            cpuinfo["core_id"] = "0"
                        key_list[i] = key_list[i].replace("%d", str(int(cpuinfo["core_id"])))
                    elif "%b" in key_list[i]:
                        key_list[i] = key_list[i].replace("%b", str(int(cpuinfo["bank_id"])))
                    elif "%n" in key_list[i]:
                        key_list[i] = key_list[i].replace("%n", str(int(cpuinfo["cha_id"])))
                    elif "%t" in key_list[i]:
                        if cpuinfo["thread_id"] == 'NA' or cpuinfo["thread_id"] == 'None' or cpuinfo["thread_id"] == None:
                            # = logger_cof("onekeylog.log")
                            news = "WARNING: No thread id. Assume 0..."+ str(key_list)
                            write_log(news)
                            # print("WARNING: No thread id. Assume 0...", key_list)
                            cpuinfo["thread_id"] = '0'
                        key_list[i] = key_list[i].replace("%t", cpuinfo["thread_id"])
                    elif "%o" in key_list[i]:
                        key_list[i] = key_list[i].replace("%o", hex(icx_reg_map[reg][1] + int(icx_reg_map["RETRY_RD_CH_NUM"][0], 16) * icx_reg_map["RETRY_RD_CH_NUM"][1]))
                    elif "%2o" in key_list[i]:
                        key_list[i] = key_list[i].replace("%2o", hex(icx_reg_map[reg][1] + int(icx_reg_map["RETRY_RD_SET2_CH_NUM"][0], 16) * icx_reg_map["RETRY_RD_SET2_CH_NUM"][1]))
                data_dic = get_dic_key(key_list, value)
        else:
            icx_reg_map[reg][0] = hex(int(value, 16))
    else:
        print("WARNING: icx_reg_map not found %s" %reg)
        write_log("WARNING: icx_reg_map not found %s" %reg)
        # raise Exception("WARNING: icx_reg_map not found %s" %reg)
    return data_dic

# according to the input cputype, return the corresponding inspurrawreg.txt.
def get_inspur_reg_map(cputype):
    reg_map = []
    with open(cputype.lower()+"_inspurrawreg.txt", "r") as regname:
        reglist = regname.readlines()
        for line in reglist:
            reg_map.append(line.strip().split(","))
    return reg_map

# merge the dict2 to dict1
def merge_dic(dic1, dic2):
    for key in dic2.keys():
        if key in dic1.keys():
            if isinstance(dic1[key], dict) and isinstance(dic2[key], dict):
                merge_dic(dic1[key], dic2[key])
            else:
                if (dic1[key] != dic2[key]):
                    if dic1[key] == "N/A":
                        dic1[key] = dic2[key]
                    else:
                        #logger = logger_cof("onekeylog.log")
                        news = "WARNING: Duplicate regs with different value: {} {} {}".format(key, dic1[key], dic2[key])
                        write_log(news)
                        # print("WARNING: Duplicate regs with different value: ", key, dic1[key], dic2[key])
        else:
            dic1.update({key: dic2[key]})
    return dic1

def logger_cof(log_path="onekeylog.log", logging_name="onekeylog"):
    return

logger = None

def init_logger(logfile="convertor_log.log"):
    global logger
    if not logger:
        logger = open(logfile, "w")      

def write_log(log_text):
    logger.write(log_text+"\n")
        
def stop_logger():
    global logger
    logger.close()




