{
  "log_cputype_re" : "PROC_ID: (\\w{2})-(\\w{2})-(\\w{2})-\\w{2}-\\w{2}-\\w{2}-\\w{2}-\\w{2}",
  "raw_cputype_re" :  "CpuType: ([A-Z]{3}),",
  "fw_info" : [{"bmc_fw_version" :  "dev_name: Activate\\(BMC[\\d]{1,3}\\), dev_version: ([\\w.()-:\\/ ]+) }"}, {"bios_id" :  "dev_name: BIOS, dev_version: ([\\w.():\\/ ]+) }"}, {"me_fw_ver" :  "dev_name: ME, dev_version: ([\\w.\\/:() ]+) }"}],
  "crashdump_all" : [{"timestamp" :  "Time: ([\\w-]+:[\\w-]+:[\\w-]+\\+[\\w-]+:[\\w-]+),"}, {"trigger_type" :  "Collect: ([\\w() ]{1,25}),"}, {"LogIndex" :  "HardwareErrorLogNumber: (\\d+),"}],
  "cpuinfo" : [{"socket_id" :  "CPU: (\\d+),"}, {"core_id" :  "Core: (\\w+),"}, {"thread_id" :  "Thread: (\\w+),"}, {"cha_id" : "CHAId: (\\d+),"}, {"bank_id" :  "Module: Bank(\\d+)\\([\\w\\d_ ]+\\),"}]
}