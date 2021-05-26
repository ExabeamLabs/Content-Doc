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
    """"Image":"({process}({directory}[^"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000}))"""",
    """"TargetFilename":"({file_path}({file_parent}[^"]{0,2000}?[\\\/]{1,2000})?({file_name}[^"\\\/]{1,2000}?(\.({file_ext}\w+))?))"""",
    """"Domain":"(NT AUTHORITY|({domain}[^"]{1,2000}))""",
    """"AccountName":"(SYSTEM|({user}[^"]{1,2000}))""",
    """"ProcessID":({pid}\d{1,100})""",
    """"ProcessGuid":"({process_guid}[^"]{1,2000})""",
    """"ParentProcessGuid":"({parent_process_guid}[^"]{1,2000})""",
    """"LogonId":"({logon_id}[^"]{1,2000})""",
    """"Hashes":"[^]]{0,2000}MD5=({md5}[^,\s]{1,2000}),""",
    """"Hostname":"({host}[^"]{1,2000})""",
    """"CommandLine":"\s{0,100}({command_line}[^,]{1,2000}?)\s{0,100}",""",
    """"ParentImage":"({parent_process}({parent_directory}[^"]{0,2000}?[\\\/]{1,2000})?({parent_process_name}[^"\\\/]{1,2000}))"""",
    """"EventID":({event_code}\d{1,100})""",
    """ProviderGuid":"({provider_guid}[^"]{1,2000})""",
    """"Task":({task}\d{1,100})""",
    """"OpcodeValue":({opcode_value}\d{1,100})""",
    """"User":"(((?i)NT AUTHORITY|({domain}[^\\]{1,2000}))[\\]{1,2000})?((?i)SYSTEM|LOCAL SERVICE|NETWORK SERVICE|({user}[^"]{1,2000}))"""",
    """"LogonGuid":"({logon_guid}[^"]{1,2000})""",
    """"Hashes":"[^]]{0,2000}SHA256=({sha256}[^",]{1,2000})""",
    """"ParentCommandLine":"\s{0,100}({parent_command_line}[^,]{1,2000}?)\s{0,100}",""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path" ]
}
```