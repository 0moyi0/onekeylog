# -*- coding: utf-8 -*-
# pylint: disable=line-too-long, import-error
# INTEL CONFIDENTIAL
# Copyright 2010 2019 Intel Corporation
#
# The source code  contained or  described herein and  all documents related to
# the source code  ("Material") are owned by Intel Corporation or its suppliers
# or licensors.  Title to the  Material  remains with  Intel Corporation or its
# suppliers  and licensors. The Material contains trade secrets and proprietary
# and  confidential  information  of  Intel  or  its  suppliers  and  licensors.
# The Material  is protected  by worldwide  copyright and trade secret laws and
# treaty provisions.  No part of the Material  may  be used, copied, reproduced,
# modified, published, uploaded, posted, transmitted, distributed, or disclosed
# in any way without Intel's prior express written permission. No license under
# any  patent,  copyright, trade secret or other intellectual property right is
# granted  to  or conferred upon you by disclosure or delivery of the Materials,
# either expressly, by implication, inducement, estoppel or otherwise.
# Any license under such intellectual property rights must be express and
# approved by Intel in writing.
#!/usr/bin/env python
import math

#####################################
# Helpers
#####################################

def inverseDict(d):
  return dict((v2, k2) for k2, v2 in d.items())

def dictStr2Val(d, base):
  return dict((k2, int(v2, base)) for k2, v2 in d.items())

#####################################
# MESH
#####################################

TARGET_LOC_PORT_BY_VAL = {
  0x00: 'KTI0',
  0x01: 'KTI1',
  0x02: 'KTI2',
  0x03: 'KTI3',
  0x04: 'IMC0',
  0x05: 'IMC1',
  0x06: 'IMC2',
  0x07: 'IMC3',
  0x08: 'IMC4',
  0x09: 'IMC5',
  0x0A: 'IMC6',
  0x0B: 'IMC7',
  0x0C: 'IMC8',
  0x0D: 'IMC9',
  0x0E: 'IMC10',
  0x0F: 'IMC11',
  0x10: 'IMC12',
  0x11: 'IMC13',
  0x14: 'PCIE0',
  0x15: 'PCIE1',
  0x16: 'PCIE2',
  0x17: 'PCIE3',
  0x18: 'PCIE4',
  0x19: 'PCIE5',
  0x1A: 'UBOX'
}

#####################################
# CACHE
#####################################

SF_STATE_BY_VAL = {
  0: 'i',
  1: 's',
  2: 'e',
  3: 'h'
}
SF_STATE = inverseDict(SF_STATE_BY_VAL)

LLC_STATE_BY_VAL = {
  0: 'i',
  1: 's',
  2: 'e',
  3: 'm',
  4: 'f',
  5: 'd',
  7: 'p'
}
LLC_STATE = inverseDict(LLC_STATE_BY_VAL)

CACHE_STATE = {
  'SF_E' :     SF_STATE['e'],
  'SF_S' :     SF_STATE['s'],
  'SF_H' :     SF_STATE['h'],
  'LLC_M': 8 | LLC_STATE['m'],
  'LLC_E': 8 | LLC_STATE['e'],
  'LLC_S': 8 | LLC_STATE['s'],
  'LLC_I': 8 | LLC_STATE['i'],
  'LLC_F': 8 | LLC_STATE['f'],
  'LLC_P': 8 | LLC_STATE['p'],
  'LLC_D': 8 | LLC_STATE['d'],
}
CACHE_STATE_BY_VAL = inverseDict(CACHE_STATE)

#####################################
# INGRESS
#####################################

NUM_IRQ_ENTRIES = 32
NUM_PRQ_ENTRIES = 24
NUM_RPQ_ENTRIES = 24

IGR_ADDR_PRQ_LSB = 0
IGR_ADDR_RPQ_LSB = NUM_PRQ_ENTRIES
IGR_ADDR_IRQ_LSB = NUM_PRQ_ENTRIES + NUM_RPQ_ENTRIES

IGR_ARBQ_IDX = {
  'ISMQ': 0,
  'IPQ' : 1,
  'RRQ' : 2,
  'WBQ' : 3,
  'IRQ' : 4,
  'PRQ' : 5,
  'TO'  : 6
}
IGR_ARBQ_IDX_BY_VAL = inverseDict(IGR_ARBQ_IDX)

INGR_RETRY_IRQ_IDX = 0
INGR_RETRY_PRQ_IDX = 1
INGR_RETRY_IPQ_IDX = 2
INGR_RETRY_RRQ_IDX = 3
INGR_RETRY_EWB_IDX = 4

IPQ  = '111'
RRQ  = '101'
WBQ  = '100'
IRQ  = '001'
ISMQ = '000'

ISMQ_FSM = {
  'Ismq_Idle': 0,
  'Arb_Valid': 1,
  'Wcmp': 2,
  'Wdata': 3,
  'Wdata_Wcmp': 4,
  'Wxsnp': 5,
  'Pending': 6,
  'Wdata_Wcmp_Split': 7,
  'Arb_Valid_Wcmp': 8,
  'Pending_Wcmp': 9,
  'Arb_Valid_Wdata_Wcmp_Split': 10,
  'Pending_Wdata_Wcmp_Split': 11,
  'Arb_Valid_Wdata_Wcmp': 12,
  'Pending_Wdata_Wcmp': 13,
  'Wfwd': 14,
  'Arb_Valid_Wxsnp': 15,
  'Pending_Wxsnp': 16,
}
ISMQ_FSM_BY_VAL = inverseDict(ISMQ_FSM)

ISMQ_SNP_RSP = {
  'RspI'      : 0b0010,
  'RspS'      : 0b0000,
  'RspIFwdM'  : 0b0001,
  'RspM'      : 0b0011,
  'RspIFwd'   : 0b0110,
  'RspSFwd'   : 0b0100,
  'RspVFwd'   : 0b1010,
  'RspTrivial': 0b1100,
  'RspV'      : 0b1110,
  'RspNack'   : 0b1111
}
ISMQ_SNP_RSP_BY_VAL = inverseDict(ISMQ_SNP_RSP)

IGR_QSTATE = {
  'Drain' : 0,
  'Normal': 1,
  'Count' : 2,
  'Starve': 3
}
IGR_QSTATE_BY_VAL = inverseDict(IGR_QSTATE)

NUM_TOR_RETRY_RSP = 10

CHA_INGR_RETRY_CRD_BY_VAL = {
  0x0 : 'ad_req_vn0',
  0x1 : 'ad_rsp_vn0',
  0x2 : 'bl_rsp_vn0',
  0x3 : 'bl_wb_vn0',
  0x4 : 'bl_ncb_vn0',
  0x5 : 'bl_ncs_vn0',
  0x6 : 'ak_non_kti',
  0x7 : 'iv_non_kti',
  0x8 : 'ha',
  0x9 : 'unknown',
  0xA : 'llc_vic',
  0xB : 'sf_vic',
  0xC : 'victim',
  0xD : 'llc_way',
  0xE : 'sf_way',
  0xF : 'allowsnoop',
  0x10: 'pa'
}

#####################################
# SAD
#####################################

SAD_RESULT_BY_VAL = {
  0: 'HOM',
  1: 'MMIO',
  2: 'CFG',
  3: 'MMIO_PTL',
  4: 'IO',
  5: 'LT',
  6: 'SPECIAL',
  7: 'ABORT'
}

SAD_ATTR_BY_VAL = {
  0: 'DRAM',
  1: 'MMCFG',
  2: 'DDRT',
  3: 'HBM'
}

#####################################
# TOR
#####################################

NUM_TOR_ENTRIES = 32

IDI_OPCODES_VALSTR = {
  'CRd'             : '00000001',
  'CRd_UC'          : '00000101',
  'CRd_Pref'        : '00010001',
  'DRd'             : '00000010',
  'DRd_Pref'        : '00010010',
  'DRd_Opt'         : '00000100',
  'DRd_Opt_Pref'    : '00010100',
  'DRdPTE'          : '00000110',
  'DRd_NS'          : '00010011',
  'SetMonitor'      : '00000011',
  'RFO'             : '00000000',
  'RFO_Pref'        : '00010000',
  'PRd'             : '00000111',
  'UCRdF'           : '00001110',
  'CLFlush'         : '00011000',
  'CLFlush_Opt'     : '00011010',
  'CLWB'            : '00011100',
  'WiL'             : '00001111',
  'WCiL'            : '00001101',
  'WCiLF'           : '00001100',
  'WCiL_NS'         : '00010101',
  'WCiLF_NS'        : '00010110',
  'RFOWr'           : '00011111',
  'RdCurr'          : '00011110',
  'PCommit'         : '00001001',
  'CLCleanse'       : '00111100',
  'Enqueue'         : '00001000',
  'LLCWBInv'        : '01001001',
  'LLCWB'           : '01001011',
  'LLCInv'          : '01001000',
  'ItoM'            : '10001000',
  'ItoMCacheNear'   : '10101000',
  'RdCurrCacheNear' : '10101001',
  'SpecItoM'        : '10001010',
  'ItoMWr'          : '10001001',
  'ItoMWr_WT'       : '10001011',
  'ItoMWr_NS'       : '10000001',
  'ItoMWR_WT_NS'    : '10010111',
  'MemPushWr'       : '10001101',
  'MemPushWr_NS'    : '10011101',
  'PrefCode'        : '10011001',
  'PrefData'        : '10011010',
  'PrefRFO'         : '10011000',
  'WbMtoI'          : '10000100',
  'WbMtoE'          : '10000101',
  'WbEFtoI'         : '10000110',
  'WbEFtoE'         : '10000111',
  'WbOtoI'          : '10010100',
  'WbOtoE'          : '10010101',
  'WbStoI'          : '10001100',
  'WbPushHint'      : '10100100',
  'CLDemote'        : '10000000',
  'PortIn'          : '11011100',
  'IntA'            : '11010100',
  'Lock'            : '11011111',
  'SplitLock'       : '11011110',
  'Unlock'          : '11010011',
  'SpCyc'           : '11000000',
  'ClrMonitor'      : '11010001',
  'PortOut'         : '11010101',
  'IntPriUp'        : '11011011',
  'IntLog'          : '11011001',
  'IntPhy'          : '11011010',
  'EOI'             : '11011000',
  'NOP'             : '11010000'
}
IDI_OPCODES = dictStr2Val(IDI_OPCODES_VALSTR, 2)
IDI_OPCODES_BY_VAL = inverseDict(IDI_OPCODES)

ISMQ_OPCODES_VALSTR = {
  'RSPI'                   : '000000',
  'RSPS'                   : '000001',
  'RSPDATAM'               : '000010',
  'RSPIFWDM'               : '000011',
  'PULLDATA'               : '000100',
  'PULLDATABOGUS'          : '000101',
  'CMP'                    : '000110',
  'CMP_FWDCODE'            : '000111',
  'CMP_FWDINVITOE'         : '001000',
  'CMP_PULLDATA'           : '001001',
  'CMP_FWDINVOWN'          : '001011',
  'DATAC_CMP'              : '001100',
  'DATAC_CMP_RSPI'         : '001101',
  'FAKECYCLE'              : '010000',
  'GNTE_CMP'               : '010011',
  'GNTE_CMP_RSPI'          : '010100',
  'GNTE_CMP_PULLDATA'      : '010111',
  'GNTE_CMP_RSPI_PULLDATA' : '011000',
  'VICTIM'                 : '011011',
  'GSRISINMSTATE'          : '011101',
  'DATANC'                 : '011110',
  'DATAC'                  : '100000',
  'RSPIFWDFE'              : '100011',
  'RSPSFWDFE'              : '100100',
  'RSPV'                   : '100110',
  'RSPVFWDV'               : '100111',
  'TOR_TIMEOUT'            : '110000',
  'FWDCNFLT'               : '100101',
  'RSPNACK'                : '110010',
  'LLCVICTIM'              : '110001',
  'RSPIFWDMPTL'            : '110011',
  'PULLDATAPTL'            : '110100'
}
ISMQ_OPCODES = dictStr2Val(ISMQ_OPCODES_VALSTR, 2)
ISMQ_OPCODES_BY_VAL = inverseDict(ISMQ_OPCODES)

IRQ_PMSeqInvd               = '00111001'

KTI_REQ_OPCODES_VALSTR = {
  'RdCur'               : '0000',
  'RdCode'              : '0001',
  'RdData'              : '0010',
  'RdDataMig'           : '0011',
  'RdInvOwn'            : '0100',
  'InvXtoI'             : '0101',
  'PushHint'            : '0110',
  'InvItoE'             : '0111',
  'RSVD8'               : '1000',
  'RSVD9'               : '1001',
  'RSVD10'              : '1010',
  'RSVD11'              : '1011',
  'RdInv'               : '1100',
  'RSVD13'              : '1101',
  'RSVD14'              : '1110',
  'InvItoM'             : '1111'
}
KTI_REQ_OPCODES = dictStr2Val(KTI_REQ_OPCODES_VALSTR, 2)
KTI_REQ_OPCODES_BY_VAL = inverseDict(KTI_REQ_OPCODES)

KTI_SNP_OPCODES_VALSTR = {
  'SnpCur'              : '0000',
  'SnpCode'             : '0001',
  'SnpData'             : '0010',
  'SnpDataMig'          : '0011',
  'SnpInvOwn'           : '0100',
  'SnpInv'              : '0101',
  'RSVD6'               : '0110',
  'RSVD7'               : '0111',
  'SnpFCur'             : '1000',
  'SnpFCode'            : '1001',
  'SnpFData'            : '1010',
  'SnpFDataMig'         : '1011',
  'SnpFInvOwn'          : '1100',
  'SnpFInv'             : '1101',
  'RSVD14'              : '1110'
}
KTI_SNP_OPCODES = dictStr2Val(KTI_SNP_OPCODES_VALSTR, 2)
KTI_SNP_OPCODES_BY_VAL = inverseDict(KTI_SNP_OPCODES)

KTI_WB_OPCODES_VALSTR = {
  'WbMtoI'               : '0000',
  'WbMtoS'               : '0001',
  'WbMtoE'               : '0010',
  'NonSnpWr'             : '0011',
  'WbMtoIPtl'            : '0100',
  'RSVD5'                : '0101',
  'WbMtoEPtl'            : '0110',
  'NonSnpWrPtl'          : '0111',
  'WbPushMtoI'           : '1000',
  'RSVD9'                : '1001',
  'RSVD10'               : '1010',
  'WbFlush'              : '1011',
  'EvctCln'              : '1100',
  'NonSnpRd'             : '1101',
  'RSVD14'               : '1110'
}
KTI_WB_OPCODES = dictStr2Val(KTI_WB_OPCODES_VALSTR, 2)
KTI_WB_OPCODES_BY_VAL = inverseDict(KTI_WB_OPCODES)

TOR_OPCODES = {
  "CRd"                    : int(IRQ + IDI_OPCODES_VALSTR['CRd'],2),
  "CRd_UC"                 : int(IRQ + IDI_OPCODES_VALSTR['CRd_UC'],2),
  "CRd_Pref"               : int(IRQ + IDI_OPCODES_VALSTR['CRd_Pref'],2),
  "UCRdF"                  : int(IRQ + IDI_OPCODES_VALSTR['UCRdF'],2),
  "SetMonitor"             : int(IRQ + IDI_OPCODES_VALSTR['SetMonitor'],2),
  "DRd"                    : int(IRQ + IDI_OPCODES_VALSTR['DRd'],2),
  "DRd_Pref"               : int(IRQ + IDI_OPCODES_VALSTR['DRd_Pref'],2),
  "DRd_Opt"                : int(IRQ + IDI_OPCODES_VALSTR['DRd_Opt'],2),
  "DRd_Opt_Pref"           : int(IRQ + IDI_OPCODES_VALSTR['DRd_Opt_Pref'],2),
  "DRd_NS"                 : int(IRQ + IDI_OPCODES_VALSTR['DRd_NS'],2),
  "PRd"                    : int(IRQ + IDI_OPCODES_VALSTR['PRd'],2),
  "DRdPTE"                 : int(IRQ + IDI_OPCODES_VALSTR['DRdPTE'],2),
  "RFO"                    : int(IRQ + IDI_OPCODES_VALSTR['RFO'],2),
  "RFO_Pref"               : int(IRQ + IDI_OPCODES_VALSTR['RFO_Pref'],2),
  "RFOWr"                  : int(IRQ + IDI_OPCODES_VALSTR['RFOWr'],2),
  "ItoM"                   : int(IRQ + IDI_OPCODES_VALSTR['ItoM'],2),
  "ItoMCacheNear"          : int(IRQ + IDI_OPCODES_VALSTR['ItoMCacheNear'],2),
  "SpecItoM"               : int(IRQ + IDI_OPCODES_VALSTR['SpecItoM'],2),
  "ItoMWr"                 : int(IRQ + IDI_OPCODES_VALSTR['ItoMWr'],2),
  "ItoMWr_WT"              : int(IRQ + IDI_OPCODES_VALSTR['ItoMWr_WT'],2),
  "ItoMWr_NS"              : int(IRQ + IDI_OPCODES_VALSTR['ItoMWr_NS'],2),
  "ItoMWR_WT_NS"           : int(IRQ + IDI_OPCODES_VALSTR['ItoMWR_WT_NS'],2),
  "MemPushWr"              : int(IRQ + IDI_OPCODES_VALSTR['MemPushWr'],2),
  "MemPushWr_NS"           : int(IRQ + IDI_OPCODES_VALSTR['MemPushWr_NS'],2),
  "PrefData"               : int(IRQ + IDI_OPCODES_VALSTR['PrefData'],2),
  "PrefCode"               : int(IRQ + IDI_OPCODES_VALSTR['PrefCode'],2),
  "PrefRFO"                : int(IRQ + IDI_OPCODES_VALSTR['PrefRFO'],2),
  "WbMtoI"                 : int(IRQ + IDI_OPCODES_VALSTR['WbMtoI'],2),
  "WbMtoE"                 : int(IRQ + IDI_OPCODES_VALSTR['WbMtoE'],2),
  "WbEFtoI"                : int(IRQ + IDI_OPCODES_VALSTR['WbEFtoI'],2),
  "WbEFtoE"                : int(IRQ + IDI_OPCODES_VALSTR['WbEFtoE'],2),
  "WbOtoI"                 : int(IRQ + IDI_OPCODES_VALSTR['WbOtoI'],2),
  "WbOtoE"                 : int(IRQ + IDI_OPCODES_VALSTR['WbOtoE'],2),
  "WbStoI"                 : int(IRQ + IDI_OPCODES_VALSTR['WbStoI'],2),
  "WbPushHint"             : int(IRQ + IDI_OPCODES_VALSTR['WbPushHint'],2),
  "WiL"                    : int(IRQ + IDI_OPCODES_VALSTR['WiL'],2),
  "WCiL"                   : int(IRQ + IDI_OPCODES_VALSTR['WCiL'],2),
  "WCiLF"                  : int(IRQ + IDI_OPCODES_VALSTR['WCiLF'],2),
  "WCiL_NS"                : int(IRQ + IDI_OPCODES_VALSTR['WCiL_NS'],2),
  "WCiLF_NS"               : int(IRQ + IDI_OPCODES_VALSTR['WCiLF_NS'],2),
  "WbInvd"                 : int(IRQ + IDI_OPCODES_VALSTR['LLCWBInv'],2),
  "LLCWB"                  : int(IRQ + IDI_OPCODES_VALSTR['LLCWB'],2),
  "PMSeqInvd"              : int(IRQ + IRQ_PMSeqInvd,2),
  "Invd"                   : int(IRQ + IDI_OPCODES_VALSTR['LLCInv'],2),
  "CLFlush"                : int(IRQ + IDI_OPCODES_VALSTR['CLFlush'],2),
  "PCommit"                : int(IRQ + IDI_OPCODES_VALSTR['PCommit'],2),
  "CLCleanse"              : int(IRQ + IDI_OPCODES_VALSTR['CLCleanse'],2),
  "CLFlush_Opt"            : int(IRQ + IDI_OPCODES_VALSTR['CLFlush_Opt'],2),
  "CLWB"                   : int(IRQ + IDI_OPCODES_VALSTR['CLWB'],2),
  "CLDemote"               : int(IRQ + IDI_OPCODES_VALSTR['CLDemote'],2),
  "RdCurr"                 : int(IRQ + IDI_OPCODES_VALSTR['RdCurr'],2),
  "RdCurrCacheNear"        : int(IRQ + IDI_OPCODES_VALSTR['RdCurrCacheNear'],2),
  "CBO_EOI"                : int(IRQ + IDI_OPCODES_VALSTR['EOI'],2),
  "IntPriUp"               : int(IRQ + IDI_OPCODES_VALSTR['IntPriUp'],2),
  "IntLog"                 : int(IRQ + IDI_OPCODES_VALSTR['IntLog'],2),
  "IntPhy"                 : int(IRQ + IDI_OPCODES_VALSTR['IntPhy'],2),
  "IntA"                   : int(IRQ + IDI_OPCODES_VALSTR['IntA'],2),
  "Lock"                   : int(IRQ + IDI_OPCODES_VALSTR['Lock'],2),
  "SpCyc"                  : int(IRQ + IDI_OPCODES_VALSTR['SpCyc'],2),
  "SplitLock"              : int(IRQ + IDI_OPCODES_VALSTR['SplitLock'],2),
  "Unlock"                 : int(IRQ + IDI_OPCODES_VALSTR['Unlock'],2),
  "PortIn"                 : int(IRQ + IDI_OPCODES_VALSTR['PortIn'],2),
  "PortOut"                : int(IRQ + IDI_OPCODES_VALSTR['PortOut'],2),
  "ClrMonitor"             : int(IRQ + IDI_OPCODES_VALSTR['ClrMonitor'],2),
  "KRdCur"                 : int(RRQ + '0000' + KTI_REQ_OPCODES_VALSTR['RdCur'],2),
  "KRdCode"                : int(RRQ + '0000' + KTI_REQ_OPCODES_VALSTR['RdCode'],2),
  "KRdData"                : int(RRQ + '0000' + KTI_REQ_OPCODES_VALSTR['RdData'],2),
  "KRdDataMigratory"       : int(RRQ + '0000' + KTI_REQ_OPCODES_VALSTR['RdDataMig'],2),
  "KRdInvOwn"              : int(RRQ + '0000' + KTI_REQ_OPCODES_VALSTR['RdInvOwn'],2),
  "KInvXtoI"               : int(RRQ + '0000' + KTI_REQ_OPCODES_VALSTR['InvXtoI'],2),
  "KInvItoE"               : int(RRQ + '0000' + KTI_REQ_OPCODES_VALSTR['InvItoE'],2),
  "KInvItoM"               : int(RRQ + '0000' + KTI_REQ_OPCODES_VALSTR['InvItoM'],2),
  "KRdInvOwnE"             : int(RRQ + '0000' + KTI_REQ_OPCODES_VALSTR['RdInv'],2),
  "KWbIData"               : int(WBQ + '0000' + KTI_WB_OPCODES_VALSTR['WbMtoI'],2),
  "KWbSData"               : int(WBQ + '0000' + KTI_WB_OPCODES_VALSTR['WbMtoS'],2),
  "KWbEData"               : int(WBQ + '0000' + KTI_WB_OPCODES_VALSTR['WbMtoE'],2),
  "KNonSnpWr"              : int(WBQ + '0000' + KTI_WB_OPCODES_VALSTR['NonSnpWr'],2),
  "KEvctCln"               : int(WBQ + '0000' + KTI_WB_OPCODES_VALSTR['EvctCln'],2),
  "KNonSnpRd"              : int(WBQ + '0000' + KTI_WB_OPCODES_VALSTR['NonSnpRd'],2),
  "KWbIDataPtl"            : int(WBQ + '0000' + KTI_WB_OPCODES_VALSTR['WbMtoIPtl'],2),
  "KWbEDataPtl"            : int(WBQ + '0000' + KTI_WB_OPCODES_VALSTR['WbMtoEPtl'],2),
  "KNonSnpWrPtl"           : int(WBQ + '0000' + KTI_WB_OPCODES_VALSTR['NonSnpWrPtl'],2),
  "KWbPushMtoI"            : int(WBQ + '0000' + KTI_WB_OPCODES_VALSTR['WbPushMtoI'],2),
  "KWbFlush"               : int(WBQ + '0000' + KTI_WB_OPCODES_VALSTR['WbFlush'],2),
  "SnpCur"                 : int(IPQ + '0000' + KTI_SNP_OPCODES_VALSTR['SnpCur'],2),
  "SnpCode"                : int(IPQ + '0000' + KTI_SNP_OPCODES_VALSTR['SnpCode'],2),
  "SnpData"                : int(IPQ + '0000' + KTI_SNP_OPCODES_VALSTR['SnpData'],2),
  "SnpDataMigratory"       : int(IPQ + '0000' + KTI_SNP_OPCODES_VALSTR['SnpDataMig'],2),
  "SnpInvOwn"              : int(IPQ + '0000' + KTI_SNP_OPCODES_VALSTR['SnpInvOwn'],2),
  "SnpInvItoE"             : int(IPQ + '0000' + KTI_SNP_OPCODES_VALSTR['SnpInv'],2),
  "RspI"                   : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['RSPI'],2),
  "RspS"                   : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['RSPS'],2),
  "RspV"                   : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['RSPV'],2),
  "RspDataM"               : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['RSPDATAM'],2),
  "RspIFwdMPtl"            : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['RSPIFWDMPTL'],2),
  "RspIFwdM"               : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['RSPIFWDM'],2),
  "RspIFwdFE"              : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['RSPIFWDFE'],2),
  "RspSFwdFE"              : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['RSPSFWDFE'],2),
  "RspNack"                : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['RSPNACK'],2),
  "RspVFwdV"               : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['RSPVFWDV'],2),
  "PullData"               : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['PULLDATA'],2),
  "PullDataBogus"          : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['PULLDATABOGUS'],2),
  "Cmp"                    : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['CMP'],2),
  "Cmp_FwdCode"            : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['CMP_FWDCODE'],2),
  "Cmp_FwdInvItoE"         : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['CMP_FWDINVITOE'],2),
  "Cmp_PullData"           : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['CMP_PULLDATA'],2),
  "FwdCnflt"               : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['FWDCNFLT'],2),
  "Cmp_FwdInvOwn"          : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['CMP_FWDINVOWN'],2),
  "DataC"                  : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['DATAC'],2),
  "DataNC"                 : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['DATANC'],2),
  "DataC_Cmp"              : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['DATAC_CMP'],2),
  "FakeCycle"              : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['FAKECYCLE'],2),
  "Victim"                 : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['VICTIM'],2),
  "LLCVictim"              : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['LLCVICTIM'],2),
  "GsrIsInMstate"          : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['GSRISINMSTATE'],2),
  "TOR_TimeOut"            : int(ISMQ + '00' + ISMQ_OPCODES_VALSTR['TOR_TIMEOUT'],2)
}

TOR_OPCODES_BY_VAL = inverseDict(TOR_OPCODES)

#####################################
# HA
#####################################
CHA_HA_REQ = '00'
CHA_HA_WB  = '01'
CHA_HA_NOP = '10'

NUM_IODC_ENTRY = 14
NUM_HA_CREDIT_POOLS = 33
NUM_HA_RETRY_Q = 8

HA_RETRY_Q_BY_VAL = {
  0: 'NORM_MEMRD',
  1: 'NORM_MEMWR',
  2: 'PRI_MEMRD',
  3: 'PRI_MEMWR',
  4: 'NORM_SNP',
  5: 'PRI_SNP',
  6: 'FWD',
  7: 'NORM_MIGWR'
}

CHA_HA_NOP_IodcDealloc      = '0000'

HA_OPCODES = {
  'Nop'            : 0,
  'RdCur'          : int('1' + CHA_HA_REQ + KTI_REQ_OPCODES_VALSTR['RdCur'], 2),
  'RdCode'         : int('1' + CHA_HA_REQ + KTI_REQ_OPCODES_VALSTR['RdCode'], 2),
  'RdData'         : int('1' + CHA_HA_REQ + KTI_REQ_OPCODES_VALSTR['RdData'], 2),
  'RdDataMig'      : int('1' + CHA_HA_REQ + KTI_REQ_OPCODES_VALSTR['RdDataMig'], 2),
  'RdInvOwn'       : int('1' + CHA_HA_REQ + KTI_REQ_OPCODES_VALSTR['RdInvOwn'], 2),
  'InvXtoI'        : int('1' + CHA_HA_REQ + KTI_REQ_OPCODES_VALSTR['InvXtoI'], 2),
  'PushHint'       : int('1' + CHA_HA_REQ + KTI_REQ_OPCODES_VALSTR['PushHint'], 2),
  'InvItoE'        : int('1' + CHA_HA_REQ + KTI_REQ_OPCODES_VALSTR['InvItoE'], 2),
  'InvItoM'        : int('1' + CHA_HA_REQ + KTI_REQ_OPCODES_VALSTR['InvItoM'], 2),
  'RdInvOwnE'      : int('1' + CHA_HA_REQ + KTI_REQ_OPCODES_VALSTR['RdInv'], 2),
  'WbIData'        : int('1' + CHA_HA_WB  + KTI_WB_OPCODES_VALSTR['WbMtoI'], 2),
  'WbSData'        : int('1' + CHA_HA_WB  + KTI_WB_OPCODES_VALSTR['WbMtoS'], 2),
  'WbEData'        : int('1' + CHA_HA_WB  + KTI_WB_OPCODES_VALSTR['WbMtoE'], 2),
  'NonSnpWrData'   : int('1' + CHA_HA_WB  + KTI_WB_OPCODES_VALSTR['NonSnpWr'], 2),
  'NonSnpRd'       : int('1' + CHA_HA_WB  + KTI_WB_OPCODES_VALSTR['NonSnpRd'], 2),
  'WbFlush'        : int('1' + CHA_HA_WB  + KTI_WB_OPCODES_VALSTR['WbFlush'], 2),
  'WbIDataPtl'     : int('1' + CHA_HA_WB  + KTI_WB_OPCODES_VALSTR['WbMtoIPtl'], 2),
  'WbEDataPtl'     : int('1' + CHA_HA_WB  + KTI_WB_OPCODES_VALSTR['WbMtoEPtl'], 2),
  'NonSnpWrDataPtl': int('1' + CHA_HA_WB  + KTI_WB_OPCODES_VALSTR['NonSnpWrPtl'], 2),
  'IodcDealloc'    : int('1' + CHA_HA_NOP + CHA_HA_NOP_IodcDealloc, 2)
}
HA_OPCODES_BY_VAL = inverseDict(HA_OPCODES)

HA_DIR_STATE_BY_VAL = {
  0: 'I',
  1: 'P',
  2: 'A',
  3: 'S'
}

#####################################
# RAS
#####################################

MSCOD_BY_VAL = {
  0x0001: 'UNCORRECTABLE_DATA_ERROR',
  0x0002: 'UNCORRECTABLE_TAG_ERROR',
  0x0003: 'SAD_ERR_WB_TO_MMIO',
  0x0004: 'SAD_ERR_IA_ACCESS_TO_GSM',
  0x0005: 'SAD_ERR_CORRUPTING_OTHER',
  0x0006: 'SAD_ERR_NON_CORRUPTING_OTHER',
  0x0007: 'CORRECTABLE_DATA_ERROR',
  0x0008: 'MEM_POISON_DATA_ERROR',
  0x0009: 'SAD_ERR_CRABABORT',
  0x000A: 'PARITY_DATA_ERROR',
  0x000B: 'CORE_WB_MISS_LLC',
  0x000C: 'TOR_TIMEOUT',
  0x000D: 'ISMQ_REQ_2_INVLD_TOR_ENTRY',
  0x000E: 'HA_PARITY_TRACKER_ERROR',
  0x000F: 'COH_TT_ERR',
  0x0011: 'LLC_TAG_CORR_ERR',
  0x0012: 'LLC_STCV_CORR_ERR',
  0x0013: 'LLC_STCV_UNCORR_ERR',
  0x0016: 'MULT_TOR_ENTRY_MATCH',
  0x0017: 'MULT_LLC_WAY_TAG_MATCH',
  0x0018: 'BL_REQ_RTID_TABLE_MISS',
  0x0019: 'AK_REQ_RTID_TABLE_MISS',
  0x001C: 'IDI_JITTER_ERROR',
  0x001D: 'SEGR_PARITY_ERROR',
  0x001E: 'SINGR_PARITY_ERROR',
  0x001F: 'ADDR_PARITY_ERROR',
  0x0021: 'UNCORRECTABLE_SF_TAG_ERROR',
  0x0022: 'SF_TAG_CORR_ERR',
  0x0023: 'SF_STCV_CORR_ERR',
  0x0024: 'SF_STCV_UNCORR_ERR',
  0x0027: 'SAD_ERR_LTMEMLOCK',
  0x0028: 'LLC_TWOLM_CORR_ERR',
  0x0029: 'LLC_TWOLM_UNCORR_ERR',
  0x002A: 'ISMQ_UNEXP_RSP',
  0x002B: 'TWOLM_MULT_HIT',
  0x002C: 'HA_UNEXP_RSP',
  0x002D: 'SAD_ERR_RRQWBQ_TO_NONHOM',
  0x002E: 'SAD_ERR_IIOTONONHOM',
  0x002F: 'PARITY_REPAIR_ERROR',
  0x0031: 'SF_TWOLM_CORR_ERR',
  0x0032: 'SF_TWOLM_UNCORR_ERR',
  0x0033: 'AK_BL_UQID_PTY_ERROR',
  0x0034: 'WXSNP_WITH_SNPCOUNT_ZERO',
  0x0035: 'MEM_PUSH_WR_NS_S',
  0x0036: 'SAD_ERR_UNSECURE_UPI_ACCESS',
  0x0037: 'CLFLUSH_MMIO_HIT_M'
}
MSCOD = inverseDict(MSCOD_BY_VAL)

#####################################
#####################################

decodeMaps = {
  'IdiOpcode'            : IDI_OPCODES_BY_VAL,
  'IgrQState'            : IGR_QSTATE_BY_VAL,
  'IgrArbQIdx'           : IGR_ARBQ_IDX_BY_VAL,
  'IgrRetryCrd'          : CHA_INGR_RETRY_CRD_BY_VAL,
  'IsmqEntryU109H.Opcode': ISMQ_OPCODES_BY_VAL,
  'IsmqEntryU109H.SnpRsp': ISMQ_SNP_RSP_BY_VAL,
  'Mscod'                : MSCOD_BY_VAL,
  'LookupCacheState'     : CACHE_STATE_BY_VAL,
  'TORCacheState'        : CACHE_STATE_BY_VAL,
  'DirDramState'         : HA_DIR_STATE_BY_VAL,
  'SnpRspDirState'       : HA_DIR_STATE_BY_VAL,
  'SadResult'            : SAD_RESULT_BY_VAL,
  'SadAttr'              : SAD_ATTR_BY_VAL,
  'TargetLocPort'        : TARGET_LOC_PORT_BY_VAL,
  'HA_OriginalReq'       : HA_OPCODES_BY_VAL,
  'OriginalReq'          : TOR_OPCODES_BY_VAL,
  'FSMStatesU109H'       : ISMQ_FSM_BY_VAL
}

def coreIdDec(val, **kwargs):
  if 'iioMap' in kwargs:
      for iio in range(6):
        if ((val > 0) and (kwargs['iioMap']['meshid_iio{}'.format(iio)] == val)):
          return 'm2iosf{}'.format(iio)
  if (val == 54):
    return 'upi0'
  if (val == 55):
    return 'upi1'
  if (val == 56):
    return 'upi2'
  return 'core{}'.format(val)

def victimWayDec(val, **kwargs):
  valStr = '0x%x'%(val)

  if (val > 0):
    encWay = math.log(val, 2)
    if (encWay == int(encWay)):
      valStr = '%s (way %d)'%(valStr, int(encWay))
    else:
      valStr = '%s (multiple ways set!)'%(valStr)

  return valStr

fieldFns = {
  'CoreId': coreIdDec,
  'LLCMyOrVictimWay': victimWayDec,
  'SFMyOrVictimWay' : victimWayDec,
  'RSFMyOrVictimWay': victimWayDec
}

def decode(field, val, **kwargs):
  if (val == '' or val == None):
    return val
  if (field in decodeMaps):
    if (val in decodeMaps[field]):
      return decodeMaps[field][val]
    else:
      return 'UNKNOWN: %d'%(val)
  elif (field in fieldFns):
    return fieldFns[field](val, **kwargs)
  else:
    return val
