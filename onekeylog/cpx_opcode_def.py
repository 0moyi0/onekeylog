# -*- coding: utf-8 -*-
# pylint: disable=line-too-long, import-error
# INTEL CONFIDENTIAL
# Copyright 2022 Intel Corporation
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

# 01/17/2022    LH
#604785 3rd Gen Intel® Xeon® Processor Scalable Family, Codename Cooper Lake EDS V1 Revision 2.0 January 2022
#Section 10.6 Cooper Lake Server Processor Uncore Crashdump

'''
DWORD 0
Bits Decoding
[0] Dump Entry Valid
[1] Valid
[2] Retry
[3] In Pipe
[8:4] Slice Number
[13:9] TOR Entry Number
[19:14] Core ID
[20] Thread ID
[31:21] Request OpCode
DWORD 1
Bits Decoding
[13:0] Address[13:0]
[19:14] FSM State
[24:20] Targeted Port
[27:25] SAD Lookup Result
[31:28] Cache Lookup State
DWORD 2
Bits Decoding
[31:0] Address[46:14] 
'''


'''
Request Opcode Decoding
DW0 [31 : 21] Decoding              DW0 [31 : 21] Decoding
0x201 CRd                           0x180 SnpCur
0x202 DRd                           0x181 SnpCode
0x206 DRdPTE                        0x182 SnpData
0x207 PRd                           0x183 Snoop
0x258 Prefetch_258                  0x184 SnpInvOwn
0x25A Prefetch_25A                  0x185 SnpInvItoE
0x259 Perfetch_259                  0x18F Prefetch_18F
0x203 Set Monitor                   0x11B Victim_11B
0x200 RFO                           0x131 Victim_131
0x20C Write Invalidate_20C          0x080 Read_080
0x20D Write Invalidate_20D          0x081 Read_081
0x20F Write Invalidate_20F          0x082 Read_082
0x218 CLFlush                       0x083 Read_083
0x219 0x219                         0x084 Read_084
0x21A 0x21A                         0x085 Invalidate_085
0x21E PCIe Request                  0x086 0x086
0x229 WriteBack_229                 0x087 Invalidate_087
0x228 Invalidate                    0x08C Invalidate_08C
0x248 ItoM                          0x08F Invalidate_08F
0x244 WriteBack_244                 0x000 WriteBack_000
0x245 WriteBack_245                 0x001 WriteBack_001
0x246 WriteBack_246                 0x002 WriteBack_002
0x247 WriteBack_247                 0x003 NonSnp_Wr
0x243 WriteBack_243                 0x004 WriteBack_004
0x270 Read Monitor                  0x006 WriteBack_006
0x271 Clear Monitor                 0x007 WriteBack_007
0x27C Port In                       0x008 WriteBack_008
0x274 IntA                          0x00B WriteBack_00B
0x27F Lock                          0x00C 0x00C
0x27E Split Lock                    0x00D Read_00D
0x273 Unlock                        0x00F 0x00F
0x260 Special Cycle
0x275 Port Out
0x27B Interrupt Priority Update
0x279 Interrupt_279
0x27A Interrupt_27A
0x278 End of Interrupt
0x276 FERR
'''
TOR_OPCODES = {
    "CRd": 	0x201,
    "DRd": 	0x202,
    "DRdPTE": 	0x206,
    "PRd": 	0x207,
    "Prefetch_258": 	0x258,
    "Prefetch_25A": 	0x25A,
    "Perfetch_259": 	0x259,
    "Set Monitor": 	0x203,
    "RFO": 	0x200,
    "Write Invalidate_20C": 	0x20C,
    "Write Invalidate_20D": 	0x20D,
    "Write Invalidate_20F": 	0x20F,
    "CLFlush": 	0x218,
    "0x219": 	0x219,
    "0x21A": 	0x21A,
    "PCIe Request": 	0x21E,
    "WriteBack_229": 	0x229,
    "Invalidate": 	0x228,
    "ItoM": 	0x248,
    "WriteBack_244": 	0x244,
    "WriteBack_245": 	0x245,
    "WriteBack_246": 	0x246,
    "WriteBack_247": 	0x247,
    "WriteBack_243": 	0x243,
    "Read Monitor": 	0x270,
    "Clear Monitor": 	0x271,
    "Port In": 	0x27C,
    "IntA": 	0x274,
    "Lock": 	0x27F,
    "Split Lock": 	0x27E,
    "Unlock": 	0x273,
    "Special Cycle": 	0x260,
    "Port Out": 	0x275,
    "Interrupt Priority Update": 	0x27B,
    "Interrupt_279": 	0x279,
    "Interrupt_27A": 	0x27A,
    "End of Interrupt": 	0x278,
    "FERR": 	0x276,
    "SnpCur": 	0x180,
    "SnpCode": 	0x181,
    "SnpData": 	0x182,
    "Snoop": 	0x183,
    "SnpInvOwn": 	0x184,
    "SnpInvItoE": 	0x185,
    "Prefetch_18F": 	0x18F,
    "Victim_11B": 	0x11B,
    "Victim_131": 	0x131,
    "Read_080": 	0x080,
    "Read_081": 	0x081,
    "Read_082": 	0x082,
    "Read_083": 	0x083,
    "Read_084": 	0x084,
    "Invalidate_085": 	0x085,
    "0x086": 	0x086,
    "Invalidate_087": 	0x087,
    "Invalidate_08C": 	0x08C,
    "Invalidate_08F": 	0x08F,
    "WriteBack_000": 	0x000,
    "WriteBack_001": 	0x001,
    "WriteBack_002": 	0x002,
    "NonSnp_Wr": 	0x003,
    "WriteBack_004": 	0x004,
    "WriteBack_006": 	0x006,
    "WriteBack_007": 	0x007,
    "WriteBack_008": 	0x008,
    "WriteBack_00B": 	0x00B,
    "0x00C": 	0x00C,
    "Read_00D": 	0x00D,
    "0x00F": 	0x00F,
    'PrefRFO'                : 0x258,
    'PrefData'               : 0x25a,
    'PrefCode'               : 0x259,
    'Monitor'                : 0x203,
    'WCiLF'                  : 0x20c,
    'WCiL'                   : 0x20d,
    'WiL'                    : 0x20f,
    'PCIWiL'                 : 0x213,
    'PCIWiLF'                : 0x214,
    'CLCleanse'              : 0x219,
    'PCIRdCur'               : 0x21e,
    'LLCWBInv'               : 0x229,
    'LLCInv'                 : 0x228,
    'WbMtoI'                 : 0x244,
    'WbMtoE'                 : 0x245,
    'WbEFtoI'                : 0x246,
    'WbEFtoE'                : 0x247,
    'WbPushHint'             : 0x243,
    'RdMonitor'              : 0x270,
    'ClrMonitor'             : 0x271,
    'PortIn'                 : 0x27c,
    'SplitLock'              : 0x27e,
    'SpCyc'                  : 0x260,
    'PortOut'                : 0x275,
    'IntPriUp'               : 0x27b,
    'IntLog'                 : 0x279,
    'IntPhy'                 : 0x27a,
    'EOI'                    : 0x278,
    'SnpDataMigratory'       : 0x183,
    'PrefetchHint'           : 0x18f,
    'SFVictim'               : 0x11b,
    'LLCVictim'              : 0x131,
    'KRdCur'                 : 0x080,
    'KRdCode'                : 0x081,
    'KRdData'                : 0x082,
    'KRdDataMig'             : 0x083,
    'KRdInvOwn'              : 0x084,
    'KInvXtoI'               : 0x085,
    'KPushHint'              : 0x086,
    'KInvItoE'               : 0x087,
    'KRdInv'                 : 0x08c,
    'KInvItoM'               : 0x08f,
    'KWbMtoI'                : 0x000,
    'KWbMtoS'                : 0x001,
    'KWbMtoE'                : 0x002,
    'KNonSnpWr'              : 0x003,
    'KWbMtoIPtl'             : 0x004,
    'KWbMtoEPtl'             : 0x006,
    'KNonSnpWrPtl'           : 0x007,
    'KWbPushMtoI'            : 0x008,
    'KWbFlush'               : 0x00b,
    'KEvctCln'               : 0x00c,
    'KNonSnpRd'              : 0x00d,
    'Slot0LLCTRL'            : 0x00f,
}

    
'''
CoreId Decoding
DW0 [19 : 14]           Decoding
0 to (N Cores)          Core
40                      KTI0/1
44                      KTI2/3
43                      KTI4/5
60                      PCIE3
61                      PCIE2
62                      PCIE1
63                      PCIE0
'''
CoreId_decoding = {
    'KTI0/1':40,
    'KTI2/3':44,
    'KTI4/5': 43,
    'PCIE3' : 60,
    'PCIE2' : 61,
    'PCIE1' : 62,
    'PCIE0' : 63,
}

'''
Targeted Port Decoding
DW1 [24 : 20]   Decoding
0x00            KTI0
0x01            KTI1
0x02            KTI2
0x03            KTI3
0x04            KTI4
0x05            KTI5
0x0c            IMC0
0x0d            IMC1
0x14            PCI0
0x15            PCI1
0x16            PCI2
0x17            PCI3
0x1a            UBOX
'''
Targeted_Port_Decoding = {
    'KTI0' : 0x00,
    'KTI1' : 0x01,
    'KTI2' : 0x02,
    'KTI3' : 0x03,
    'KTI4' : 0x04,
    'KTI5' : 0x05,
    'IMC0' : 0x0c,
    'IMC1' : 0x0d,
    'PCI0' : 0x14,
    'PCI1' : 0x15,
    'PCI2' : 0x16,
    'PCI3' : 0x17,
    'UBOX' : 0x1a,
}

'''
SAD Lookup Result Decoding
DW1 [27 : 25]   Decoding
0x0             HOM
0x1             MMIO
0x2             CFG
0x3             MMIO Partial Read
0x4             IO
0x5             Intel Reserved
0x6             SPC
0x7             Intel Reserved
'''
Sad_Result_Decoding = {
    'HOM'   : 0x0,
    'MMIO'  : 0x1,
    'CFG'   : 0x2,
    'MMIO Partial Read' : 0x3,
    'IO'    : 0x4,
    'SPC'   : 0x6
}

'''
Lookup Cache State Decoding
DW1 [31 : 28]   Decoding
0x00            not implemented
0x01            SF_S
0x02            SF_E
0x03            SF_H
0x04            not implemented
0x05            not implemented
0x06            not implemented
0x07            not implemented
0x08            LLC_I
0x09            LLC_S
0x0a            LLC_E
0x0b            LLC_M
0x0c            not implemented
0x0d            not implemented
0x0e            not implemented
0x0f            not implemented
'''
CatchState_Decoding = {
    'SF_S' : 0x01,
    'SF_E' : 0x02,
    'SF_H' : 0x03,
    'LLC_I' : 0x08,
    'LLC_S' : 0x09,
    'LLC_E' : 0x0a,
    'LLC_M' : 0x0b,
}