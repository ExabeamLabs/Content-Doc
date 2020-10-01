#### Parser Content
```Java
{
Name = json-sysmon-process-created
  Vendor = Microsoft
  Product = Sysmon
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Microsoft-Windows-Sysmon""", """Process Create:""", """"AccountName":"""" ]
  Fields = [
    """"UtcTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"Image":"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+))"""",
    """"TargetFilename":"({file_path}({file_parent}[^"]*?[\\\/]+)?({file_name}[^"\\\/]+?(\.({file_ext}\w+))?))"""",
    """"Domain":"({domain}[^"]+)""",
    """"AccountName":"({user}[^"]+)""",
    """"ProcessID":({pid}\d+)""",
    """"ProcessGuid":"({process_guid}[^"]+)""",
    """"ParentProcessGuid":"({parent_process_guid}[^"]+)""",
    """"LogonId":"({logon_id}[^"]+)""",
    """Hashes:.*?,?MD5=({md5}[^\s,]+)""",
    """"Hostname":"({host}[^"]+)""",
    """"CommandLine":"\s*({command_line}.+?)\s*",""",
    """"ParentImage":"({parent_process}({parent_directory}[^"]*?[\\\/]+)?({parent_process_name}[^"\\\/]+))"""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path" ]
}
```