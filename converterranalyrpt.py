# -*- coding: utf-8 -*-
# 02/28/2022

import argparse
import os
import re
import json
import sys
import copy
from collections import OrderedDict
import opcodes_def
import cpx_opcode_def

def _read_json(filename=None):
    json_object = None
    crashfile = open(filename, 'r')
    json_object = json.load(crashfile)

#    if 'HardwareErrorLog' in json_object:
#        json_object = json_object.get("HardwareErrorLog", None)
#    else:
#        json_object = None
    crashfile.close()
    return json_object


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

def covert_cpx_tor_dump(tor_info, dw):
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
            tor_info["Core"] = tor_info["Core"].lower()
            if tor_info["Core"].startswith("core"):
                id = int(tor_info["Core"][4:])
            else:
                id = cpx_opcode_def.CoreId_decoding[tor_info["Core"].upper()]
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
                    print("ERROR: Unknown FSM State %s"%tor_info["Fsm"])
            elif isinstance(tor_info["Fsm"], int):
                dw[1] = dw[1] | (tor_info["Fsm"] & 0x3f) << 14
        else:
            print("ERROR: Unknown tor key %s" % tor_key)
    return True

def covert_tor_dump(tor_info, tordump0, tordump1, tordump2):
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
                id = int(tor_info["Core"][3:]) + 54
            elif tor_info["Core"].lower().startswith("pcie"):  # TODO "IIO" or "PCIE"?
                id = (~(int(tor_info["Core"][4:]) & 0x3) & 0x3) + 60
            else:
                print("ERROR: Unknown Core value %s"%tor_info["Core"])
                raise
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
        elif "SystemAddres" == tor_key or "SystemAddress" == tor_key:
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
    return True

def get_report_cpx_TOR_dump(Errorlist):
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
                    print("ERROR: tor dump decode failed\n", tor_info)
    return tor_data

def get_report_TOR_dump(Errorlist):

    tor_data = {}
    for error in Errorlist:
        if error.get("ErrorArch", None) == "TorDump":
            tor_info_list = error.get("TorDump Info", None)
            for tor_info in tor_info_list:
                tordump0 = [0, 0, 0, 0, 0, 0, 0, 0]
                tordump1 = [0, 0, 0, 0, 0, 0, 0, 0]
                tordump2 = [0, 0, 0, 0, 0, 0, 0, 0]
                if covert_tor_dump(tor_info, tordump0, tordump1, tordump2):
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
                    print("ERROR: tor dump decode failed\n", tor_info)
    return tor_data

imc_chn_map = {
    "0x0": ["10","3"],
    "0x1": ["10","7"],
    "0x2": ["11","3"],
    "0x3": ["12","3"],
    "0x4": ["12","7"],
    "0x5": ["13","3"]
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

reg_map = {
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

def get_dic_key(key_list, value):
    if len(key_list) >1:
        return {key_list[0]: get_dic_key(key_list[1:], value)}
    else:
        return {key_list[0]: value}

def cpx_reg_mapping(reg, value, cpuinfo):
    data_dic = {}
    if "IA32_MCi" in reg:

        if int(cpuinfo["bank_id"]) < 4:
            reg = reg.replace("MCi", "MCx")
        elif cpuinfo["cha_id"] is not None:
            reg = reg.replace("MCi", "MCc")

    if cpx_reg_map[reg]:
        # print(reg, reg_map[reg])
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
                # print(data_dic)
        else:
            cpx_reg_map[reg] = hex(int(value, 16))

    return data_dic


def reg_mapping(reg, value, cpuinfo):
    data_dic = {}
    if "IA32_MCi" in reg:

        if int(cpuinfo["bank_id"]) < 4:
            reg = reg.replace("MCi","MCx")
        elif cpuinfo["cha_id"] is not None:
            reg = reg.replace("MCi", "MCc")


    if reg_map[reg]:
        #print(reg, reg_map[reg])
        if reg_map[reg][0]:
            if '/' in reg_map[reg][0]:
                key_list = reg_map[reg][0].split("/")
                for i in range(0,len(key_list)):
                    if "%c" in key_list[i]:
                        key_list[i] = key_list[i].replace("%c", str(int(cpuinfo["socket_id"])))
                    elif "%d" in key_list[i]:
                        if cpuinfo["core_id"]  == "uncore":
                            cpuinfo["core_id"] = "0"
                        key_list[i] = key_list[i].replace("%d", str(int(cpuinfo["core_id"])))
                    elif "%b" in key_list[i]:
                        key_list[i] = key_list[i].replace("%b", str(int(cpuinfo["bank_id"])))
                    elif "%n" in key_list[i]:
                        key_list[i] = key_list[i].replace("%n", str(int(cpuinfo["cha_id"])))
                    elif "%t" in key_list[i]:
                        if cpuinfo["thread_id"] == 'NA' or cpuinfo["thread_id"] == 'None':
                            print("WARNING: No thread id. Assume 0...", key_list)
                            cpuinfo["thread_id"] = '0'
                        key_list[i] = key_list[i].replace("%t", cpuinfo["thread_id"])
                    elif "%o" in key_list[i]:
                        key_list[i] = key_list[i].replace("%o", hex(reg_map[reg][1]+int(reg_map["RETRY_RD_CH_NUM"][0], 16)*reg_map["RETRY_RD_CH_NUM"][1]))
                    elif "%2o" in key_list[i]:
                        key_list[i] = key_list[i].replace("%2o", hex(reg_map[reg][1]+int(reg_map["RETRY_RD_SET2_CH_NUM"][0], 16)*reg_map["RETRY_RD_SET2_CH_NUM"][1]))
                    
                data_dic = get_dic_key(key_list, value)
                #print(data_dic)
        else:
            reg_map[reg][0] = hex(int(value,16))

        
        
    return data_dic

def merge_dic(dic1, dic2):
    for key in dic2.keys():
        if key in dic1.keys():
            if isinstance(dic1[key], dict) and isinstance(dic2[key], dict):
                merge_dic(dic1[key], dic2[key])
            else:
                if(dic1[key]!=dic2[key]):
                    if dic1[key] == "N/A":
                        dic1[key] = dic2[key]
                    else:
                        print("WARNING: Duplicate regs with different value: ", key, dic1[key], dic2[key])
        else:
            dic1.update({key:dic2[key]})
    return dic1
    
#def convertanalyrpt(rptfile, raw_src="ALL", raw_time="ALL"):
def convertanalyrpt(jsonobj, raw_src="ALL", raw_time="ALL", cputype = 'icx'):
#    try:
#        jsonobj = _read_json(rptfile)
#    except:
#        print("can't find the erroranalyreport.")
#        return
    
    if jsonobj is None:
        print("ERROR: Unknown format erroranalyreport.")
        return None
    jsonobj = jsonobj.get("HardwareErrorLog", [])
    all_log_list = []
    crashdump_processor = {}
    for log in jsonobj:
        crashdump_all = {}
        crashdump_processor = {}  # OrderedDict()
        dump_time = log.get("Time", None)
        crashdump_all["Time"] = dump_time
        dump_src = log.get("Collect", None)
        crashdump_all["Source"] = dump_src
        crashdump_all["LogIndex"] = log.get("HardwareErrorLogNumber", None)
        valid_flag = log.get("CollectIntegrity", None)
        if raw_src != "ALL" and dump_src != raw_src:
            continue
        if raw_time != "ALL" and raw_time != dump_time:
            continue
        if 1: #(valid_flag == "Validate(0x00)"):
            error_list = log.get("ErrorEntry", None)

            for err_evt in error_list:
                cpu_info = {}
                if "ErrorArch" in err_evt.keys():
                    #print(err_evt["ErrorArch"])
                    if err_evt["ErrorArch"].startswith("CSR"):
                        continue
                    cpu_info["socket_id"] = str(err_evt.get("CPU", None))

                    #print("socket_id", cpu_info["socket_id"])
                    cpu_info["core_id"] = str(err_evt.get("Core", None))
                    #print(cpu_info["core_id"],"core_id")
                    cpu_info["thread_id"] = str(err_evt.get("Thread", None))
                    #print(err_evt.get("Module", None))
                    bank_str = err_evt.get("Module", None)
                    cpu_info["cha_id"] = (err_evt.get("CHAId", None))
                    bank_check = None
                    if bank_str:
                        bank_check = re.match(r'Bank(\d+)\([\w\d_ ]+\)', bank_str)
                        if bank_check:
                            cpu_info["bank_id"] = str(bank_check.group(1))
                            #print(cpu_info["bank_id"],"bank_id",bank_str)
                        else:
                            print("WARNING: No bank id. %s"%bank_str)

                    if not cpu_info["cha_id"] and cputype == 'icx' and bank_check:
                        if "REGISTER DUMP" in err_evt:
                            mcerrreg = err_evt["REGISTER DUMP"].get("McerrLoggingReg", None)
                            if mcerrreg:
                                srcid = int(mcerrreg,16) & 0xff
                                if srcid>=0x40 and srcid <= 0x67:
                                    if (srcid-0x40)%3+9 == int(bank_check.group(1)):
                                        cpu_info["cha_id"] = str(srcid - 0x40)
                    if "REGISTER DUMP" in err_evt.keys():
                        for reg, value in err_evt["REGISTER DUMP"].items():
                            #print(reg, value)
                            if cputype == 'icx':
                                temp_dic = reg_mapping(reg, value, cpu_info)
                            elif cputype == 'cpx':
                                temp_dic = cpx_reg_mapping(reg, value, cpu_info)
                            #print(temp_dic)
                            crashdump_processor = merge_dic(crashdump_processor, temp_dic)

                            pass
            #crashdump_processor.update()
            if cputype == 'icx':
                tor_data = get_report_TOR_dump(error_list)
                ver_id = "1a001"
            elif cputype == 'cpx':
                tor_data = get_report_cpx_TOR_dump(error_list)
                ver_id = "34001"
            else:
                tor_data = {}
                print("Error: Unknown CPU TOR dump")

            for socketid in tor_data.keys():
                if crashdump_processor.get('cpu%d' % socketid, None) == None:
                    crashdump_processor['cpu%d' % socketid] = OrderedDict()
                crashdump_processor['cpu%d' % socketid]['TOR'] = copy.deepcopy(tor_data[socketid])
                crashdump_processor['cpu%d' % socketid]['TOR']["_version"] = "0x090"+ver_id
        if crashdump_processor:
            crashdump_all["PROCESSORS"] = copy.deepcopy(crashdump_processor)
            all_log_list.append(crashdump_all)

    return crashdump_processor, all_log_list


if __name__ == "__main__":
    jsonobj = _read_json(sys.argv[1])
    convertanalyrpt(jsonobj)