import os
import re

from nose.tools import assert_equal
import nose
import convertInspurokl
# from configuration import conf_dict
from parse_analy_report import deal_report
from parse_component_log import get_component_info
from testfile.teat_dicts import dic, dic_a, dic_b, dic_mapping, type_mapping, ans_mapping, dic_icx_TOR_dump, \
    dic_cpx_TOR_dump, dic_get_icx_TOR_dump, ret_get_icx_TOR_dump, dic_get_cpx_TOR_dump, ret_get_cpx_TOR_dump
from util import _read_json, get_file_list, deal_bankid_None, get_file_retxt, get_dict_by_conf, \
    reset_dic, merge_dic, icx_reg_mapping, cpx_reg_mapping, covert_icx_tor_dump, covert_cpx_tor_dump, \
    get_report_icx_TOR_dump, get_report_cpx_TOR_dump, make_file


class TestONEKEYLOG():

    def test_read_json(self):
        errors = []
        temp, error_list = _read_json("testfile/test.json")
        dict = {'key': 'val', 'key1': 'val1', 'key2': [{'key3': 'val3'}, {'key4': 'val4'}]}
        assert_equal(temp, dict)
        temp, error_list = _read_json("testfile/test_empty.json")
        dict = None
        assert_equal(temp, dict)
        temp, error_list = _read_json("testfile/test_error.json")
        dict = None
        assert_equal(temp, dict)
        temp, error_list = _read_json("testfile/test_error1.json")
        dict = None
        assert_equal(temp, dict)

    def test_get_file_list(self):
        temp = get_file_list("testfile/test.json")
        assert_equal(temp, ['{', 'key : val,', 'key1 :  val1,', 'key2 : [{key3 :  val3}, {key4 :  val4}]', '}'])
        temp = get_file_list("testfile/test1.json")
        assert_equal(temp, [])
        dic = {
              "key" : "val",
              "key1" :  "val1",
              "key2" : [{"key3" :  "val3"}, {"key4" :  "val4"}]
        }
        temp = get_file_list(dic)
        assert_equal(temp, ['{key: val', ' key1: val1', ' key2: [{key3: val3}', ' {key4: val4}]}'])
        temp = [1, 2, 3, 4]
        temp = get_file_list(temp)
        assert_equal(temp, None)

    def test_deal_bankid_None(self):
        dic = {
           "ErrorArch": "MCA",
           "CPU": 0,
           "Core": 1,
           "Mode": "CDC"}
        flag = deal_bankid_None(dic, "Module")
        assert_equal(flag, False)
        dic["Module"]="Bank3(MLC)"
        flag = deal_bankid_None(dic, "Module")
        assert_equal(flag, True)

    def test_get_dict_by_conf(self):
        txt = get_file_retxt(dic)
        cpuinfo = get_dict_by_conf("configuration.py", "cpuinfo", txt)
        assert_equal(cpuinfo, {'socket_id': '0', 'core_id': '1', 'thread_id': None, 'cha_id': None, 'bank_id': '3'})

    def test_make_file(self):
        make_file("test", dic, 0)
        if os.path.exists("converted_test_0.json"):
            os.remove("converted_test_0.json")
        else:
            assert_equal(1, 2)

    def test_get_file_retxt(self):
        txt = get_file_retxt(dic)
        assert_equal(txt, "{ErrorArch: MCA, CPU: 0, Core: 1, Module: Bank3(MLC), Mode: CDC}")
        txt = get_file_retxt("testfile/test_retxt.json")
        assert_equal(txt, "{ErrorArch: MCA, CPU: 0, Core: 1, Module: Bank3(MLC), Mode: CDC}")
        txt = get_file_retxt("testfile/test1.json")
        assert_equal(txt, "")
        temp = [1, 2, 3, 4]
        txt = get_file_retxt(temp)
        assert_equal(txt, None)

    def test_reset_dic(self):
        dic["_version"] = ["v1.0"]
        dic["test"] = ["test"]
        new_dic = reset_dic(dic)
        assert_equal(None, new_dic)

    def test_merge_dic(self):
        merge_dic(dic_a, dic_b)
        assert_equal(dic_a, {'1': 1, '2': 2, '3': 3, '8': '8', '9': '9', '4': 4, '5': {'6': 6, '7': 7}})

    def test_reg_mapping(self):
        for i in range(len(dic_mapping)):
            temp = {}
            if "ErrorArch" in dic_mapping[i].keys():
                if dic_mapping[i]["ErrorArch"].startswith("CSR"):
                    continue
                txt = get_file_retxt(dic_mapping[i])
                cpuinfo = get_dict_by_conf("configuration.py", "cpuinfo", txt)
                if cpuinfo['bank_id'] == None:
                    deal_bankid_None(temp, "Module")
                if not cpuinfo["cha_id"] and type_mapping[i] == 'icx' and cpuinfo["bank_id"] in ['9', '10', '11']:
                    if "REGISTER DUMP" in dic_mapping[i]:
                        mcerrreg = dic_mapping[i]["REGISTER DUMP"].get("McerrLoggingReg", None)
                        if mcerrreg:
                            srcid = int(mcerrreg, 16) & 0xff
                            if srcid >= 0x40 and srcid <= 0x67:
                                if (srcid - 0x40) % 3 + 9 == int(cpuinfo["bank_id"]):
                                    cpuinfo["cha_id"] = str(srcid - 0x40)
                    if not cpuinfo["cha_id"]:
                        news = "Error: Bank{} CHA ID not found.".format(cpuinfo["bank_id"])
                register_dump = re.search("REGISTER DUMP: {(.*)}", txt, re.M | re.I)
                if register_dump:
                    register_dump_list = register_dump.group(1).replace("{", "").replace("}", "").replace("]", "").replace(
                        "[", "").split(",")
                    for info in register_dump_list:
                        reg, val = info.split(":")[0].strip(), info.split(":")[1].strip()
                        val = val.replace("Errcode:", "CC:")
                        if type_mapping[i] == 'icx':
                            temp_dic = icx_reg_mapping(reg, val, cpuinfo)
                        elif type_mapping[i] == 'cpx':
                            temp_dic = cpx_reg_mapping(reg, val, cpuinfo)
                        temp = merge_dic(temp, temp_dic)
                assert_equal(temp, ans_mapping[i])

    def test_get_report_icx_TOR_dump(self):
        tor_data = get_report_icx_TOR_dump(dic_get_icx_TOR_dump)
        assert_equal(tor_data, ret_get_icx_TOR_dump)
        # print(tor_data)

    def test_get_report_cpx_TOR_dump(self):
        tor_data = get_report_cpx_TOR_dump(dic_get_cpx_TOR_dump)
        assert_equal(tor_data, ret_get_cpx_TOR_dump)
        # print(tor_data)

    def test_covert_icx_tor_dump(self):
        error_list = []
        tordump0 = [0, 0, 0, 0, 0, 0, 0, 0]
        tordump1 = [0, 0, 0, 0, 0, 0, 0, 0]
        tordump2 = [0, 0, 0, 0, 0, 0, 0, 0]
        sign = []
        for i in dic_icx_TOR_dump:
            for j in i["TorDump Info"]:
                try:
                    # tor_info = dic_icx_TOR_dump[0]["TorDump Info"][0]
                    flag = covert_icx_tor_dump(j, tordump0, tordump1, tordump2)
                    sign.append(flag)
                except Exception as e:
                    error_list.append(str(e))
                    # assert_equal(str(e), 'ERROR: Unknown Core value uncore17')
        if error_list:
            print(error_list)
        assert_equal(error_list, ['ERROR: Unknown Core value uncore17'])
        assert_equal(sign[3], False)

    def test_covert_cpx_tor_dump(self):
        error_list = []
        sign = []
        DW = [0,0,0]
        for i in dic_cpx_TOR_dump:
            for j in i["TorDump Info"]:
                try:
                    flag = covert_cpx_tor_dump(j, DW)
                    sign.append(flag)
                except Exception as e:
                    error_list.append(str(e))
        if error_list:
            print(error_list)
        assert_equal([], error_list)
        assert_equal(sign[0], False)


if __name__ == "__main__":
    result = nose.run()
    print(result)

