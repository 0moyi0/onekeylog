# -><- coding: utf-8 -*-
# 23/07/2022

import argparse
import os
import re
import json
import copy
from collections import OrderedDict
from util import _read_json, get_dict_by_conf, get_report_icx_TOR_dump, get_report_cpx_TOR_dump, \
    cpx_reg_mapping, icx_reg_mapping, merge_dic, get_file_retxt, deal_bankid_None, make_file, write_log


# Convert the ErrorAnalyReport to the corresponding converted_XXXX_RegAnalyRpt.json file.
# @parameter - report_filename： The ErrorAnalyReport file.
# @parameter - component_info： from component log
# return - all_log_list, error_list:
# all_log_list: a list contains all crash_dump records in the ErrorAnalyReport file.
# error_list: All error messages generated when converting the ErrorAnalyReport file.
def deal_report(report_filename, component_info):
    cpu_dict, fw_info = component_info['cpu_dict'], component_info['fw_info']
    cpu_type, ver_id, sockets, cpu_info = cpu_dict['cpu_type'], cpu_dict['ver_id'], cpu_dict['sockets'], cpu_dict[
        'cpu_info']
    all_log_list = []
    error_list = []
    if cpu_type == "icx":
        mca_err_src_log = "B31_D30_F2_0xEC"
        ierrloggingreg = "B30_D00_F0_0xA4"
        mcerrloggingreg = "B30_D00_F0_0xA8"
        firstmcerrtscloreg = "B31_D30_F4_0xF8"
        firstmcerrtschireg = "B31_D30_F4_0xFC"
        firstierrtscloreg = "B31_D30_F4_0xF0"
        firstierrtschireg = "B31_D30_F4_0xF4"
    elif cpu_type == "cpx":
        mca_err_src_log = "B01_D30_F2_0xEC"
        ierrloggingreg = "B00_D08_F0_0xA4"
        mcerrloggingreg = "B00_D08_F0_0xA8"
        firstmcerrtscloreg = "B01_D30_F4_0xF8"
        firstmcerrtschireg = "B01_D30_F4_0xFC"
        firstierrtscloreg = "B01_D30_F4_0xF0"
        firstierrtschireg = "B01_D30_F4_0xF4"
    try:
        reportjsonobj, error_list = _read_json(report_filename)
        if reportjsonobj is None:
            #logger = logger_cof("onekeylog.log")
            write_log("ERROR: Unknown format erroranalyreport.")
            # print("ERROR: Unknown format erroranalyreport.")
            error_list.append((report_filename, "ERROR: Unknown format erroranalyreport."))
            return all_log_list, error_list
        json_object = reportjsonobj.get("HardwareErrorLog", [])
        for log in json_object:
            crashdump_all = {}
            txt = get_file_retxt(log)
            crashdump_all['METADATA'] = get_dict_by_conf("configuration.py", "crashdump_all", txt)
            crashdump_all['METADATA']['platform_name'] = "N/A"
            crashdump_all['METADATA']['CollectIntegrity'] = 0
            crashdump_all['METADATA']['_version'] = '0x0b0' + ver_id
            crashdump_all['METADATA']['crashdump_version'] = 'Inspur_Onekeylog_Conversion'
            crashdump_all['METADATA']['_total_time'] = "N/A"
            for fw in fw_info:  # fw_info ： the fw_info(some version) data in component.log
                crashdump_all['METADATA'][fw] = fw_info[fw]
            crashdump_all['PROCESSORS'] = {}
            error_lists = log.get("ErrorEntry", None)
            for err_evt in error_lists:
                if "ErrorArch" in err_evt.keys():
                    if err_evt["ErrorArch"].startswith("CSR"):
                        continue
                    txt = get_file_retxt(err_evt)
                    cpuinfo = get_dict_by_conf("configuration.py", "cpuinfo", txt)
                    if cpuinfo['bank_id'] == None:
                        deal_bankid_None(err_evt, "Module")
                    if not cpuinfo["cha_id"] and cpu_type == 'icx' and cpuinfo["bank_id"] in ['9','10','11']:
                        if "REGISTER DUMP" in err_evt:
                            mcerrreg = err_evt["REGISTER DUMP"].get("McerrLoggingReg", None)
                            if mcerrreg:
                                srcid = int(mcerrreg, 16) & 0xff
                                if srcid >= 0x40 and srcid <= 0x67:
                                    if (srcid - 0x40) % 3 + 9 == int(cpuinfo["bank_id"]):
                                        cpuinfo["cha_id"] = str(srcid - 0x40)
                        if not cpuinfo["cha_id"]:
                            news = "Error: Bank{} CHA ID not found.".format(cpuinfo["bank_id"])
                            error_list.append((os.path.basename(report_filename), news))
                            write_log(news)
                    register_dump = re.search("REGISTER DUMP: {(.*)}", txt, re.M | re.I)
                    if register_dump:
                        register_dump_list = register_dump.group(1).replace("{","").replace("}","").replace("]","").replace("[","").split(",")

                        for info in register_dump_list:
                            reg, val = info.split(":")[0].strip(), info.split(":")[1].strip()
                            val = val.replace("Errcode:", "CC:")
                            if cpu_type == 'icx':
                                temp_dic = icx_reg_mapping(reg, val, cpuinfo)
                            elif cpu_type == 'cpx':
                                temp_dic = cpx_reg_mapping(reg, val, cpuinfo)
                            crashdump_all['PROCESSORS'] = merge_dic(crashdump_all['PROCESSORS'], temp_dic)
            if cpu_type == 'icx':
                tor_data = get_report_icx_TOR_dump(error_lists)
            elif cpu_type == 'cpx':
                tor_data = get_report_cpx_TOR_dump(error_lists)
            else:
                tor_data = {}
                #logger = logger_cof("onekeylog.log")
                write_log("Error: Unknown CPU TOR dump")
                error_list.append((report_filename, "Error: Unknown CPU TOR dump"))
                # print("Error: Unknown CPU TOR dump")
            for socketid in tor_data.keys():
                if crashdump_all['PROCESSORS'].get('cpu%d' % socketid, None) == None:
                    crashdump_all['PROCESSORS']['cpu%d' % socketid] = OrderedDict()
                crashdump_all['PROCESSORS']['cpu%d' % socketid]['TOR'] = copy.deepcopy(tor_data[socketid])
                crashdump_all['PROCESSORS']['cpu%d' % socketid]['TOR']["_version"] = "0x090" + ver_id
            if crashdump_all['PROCESSORS']:
                crashdump_all['PROCESSORS']["_version"] = "0x0f0{}".format(ver_id)
                for socket in sockets:
                    if crashdump_all['PROCESSORS'].get('cpu%d' % socket, None) == None:
                        crashdump_all['PROCESSORS']['cpu%d' % socket] = {}
                    if crashdump_all['PROCESSORS']['cpu%d' % socket].get("uncore", None) == None:
                        crashdump_all['PROCESSORS']['cpu%d' % socket]["uncore"] = {}
                    crashdump_all['PROCESSORS']['cpu%d' % socket]["uncore"]["_version"] = "0x080%s" % ver_id
                    if crashdump_all['PROCESSORS']['cpu%d' % socket].get("MCA", None):
                        crashdump_all['PROCESSORS']['cpu%d' % socket]["MCA"]["_version"] = "0x3e0%s" % ver_id
                    if crashdump_all['PROCESSORS']['cpu%d' % socket].get("TOR", None):
                        crashdump_all['PROCESSORS']['cpu%d' % socket]["TOR"]["_version"] = "0x090%s" % ver_id
                    crashdump_all['METADATA']['cpu%d' % socket] = {
                        "core_count": "%s" % cpu_info[socket]["core_count"],
                        "cpuid": "%s" % cpu_info[socket]["cpuid"],
                        "mca_err_src_log": "N/A",
                        "package_id": "N/A",
                        "peci_id": "N/A",
                        "ppin": "%s" % cpu_info[socket]["ppin"],
                        "ucode_patch_ver": "N/A"
                    }
                    crashdump_all['METADATA']['cpu%d' % socket]['mca_err_src_log'] = crashdump_all['PROCESSORS']['cpu%d' % socket]["uncore"].get(mca_err_src_log, "N/A")
                    firstierrtsclo = crashdump_all['PROCESSORS']['cpu%d' % socket]["uncore"].get(firstierrtscloreg,"N/A")
                    firstierrtschi = crashdump_all['PROCESSORS']['cpu%d' % socket]["uncore"].get(firstierrtschireg,"N/A")
                    if firstierrtsclo and firstierrtschi and "N/A" != firstierrtsclo and "N/A" != firstierrtschi:
                        crashdump_all['METADATA']['cpu%d' % socket]['firstierrtsc'] = firstierrtschi + firstierrtsclo[2:]
                    firstmcerrtsclo = crashdump_all['PROCESSORS']['cpu%d' % socket]["uncore"].get(firstmcerrtscloreg, "N/A")
                    firstmcerrtschi = crashdump_all['PROCESSORS']['cpu%d' % socket]["uncore"].get(firstmcerrtschireg, "N/A")
                    if firstmcerrtsclo and firstmcerrtschi and "N/A" != firstmcerrtsclo and "N/A" != firstmcerrtschi:
                        crashdump_all['METADATA']['cpu%d' % socket]['firstmcerrtsc'] = firstmcerrtschi + firstmcerrtsclo[2:]
                    crashdump_all['METADATA']['cpu%d' % socket]['ierrloggingreg'] = crashdump_all['PROCESSORS']['cpu%d' % socket]["uncore"].get(ierrloggingreg, "N/A")
                    crashdump_all['METADATA']['cpu%d' % socket]['mcerrloggingreg'] = crashdump_all['PROCESSORS']['cpu%d' % socket]["uncore"].get(mcerrloggingreg, "N/A")
                all_log_list.append(crashdump_all)
                make_file(report_filename, crashdump_all, int(crashdump_all['METADATA']['LogIndex']))
    except Exception as e:
        error_list.append((report_filename, str(e)))
    return all_log_list, error_list


