#### Parser Content
```Java
{
Name = json-sysmon-process-created
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Microsoft-Windows-Sysmon""", """Process Create:""", """"AccountName":"""" ]
  Fields = [
    """"UtcTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"Image":"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+))"""",
    """"TargetFilename":"({file_path}({file_parent}[^"]*?[\\\/]+)?({file_name}[^"\\\/]+?(\.({file_ext}\w+))?))"""",
    """"Domain":"(NT AUTHORITY|({domain}[^"]+))""",
    """"AccountName":"(SYSTEM|({user}[^"]+))""",
    """"ProcessID":({pid}\d{1,100})""",
    """"ProcessGuid":"({process_guid}[^"]+)""",
    """"ParentProcessGuid":"({parent_process_guid}[^"]+)""",
    """"LogonId":"({logon_id}[^"]+)""",
    """"Hashes":"[^]]*MD5=({md5}[^,\s]+),""",
    """"Hostname":"({host}[^"]+)""",
    """"CommandLine":"\s{0,100}({command_line}[^,]+?)\s{0,100}",""",
    """"ParentImage":"({parent_process}({parent_directory}[^"]*?[\\\/]+)?({parent_process_name}[^"\\\/]+))"""",
    """"EventID":({event_code}\d{1,100})""",
    """ProviderGuid":"({provider_guid}[^"]+)""",
    """"Task":({task}\d{1,100})""",
    """"OpcodeValue":({opcode_value}\d{1,100})""",
    """"User":"(((?i)NT AUTHORITY|({domain}[^\\]+))[\\]+)?((?i)SYSTEM|LOCAL SERVICE|NETWORK SERVICE|({user}[^"]+))"""",
    """"LogonGuid":"({logon_guid}[^"]+)""",
    """"Hashes":"[^]]*SHA256=({sha256}[^",]+)""",
    """"ParentCommandLine":"\s{0,100}({parent_command_line}[^,]+?)\s{0,100}",""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path" ]
}
```