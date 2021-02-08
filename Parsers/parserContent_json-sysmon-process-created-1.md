#### Parser Content
```Java
{
Name = json-sysmon-process-created-1
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Microsoft-Windows-Sysmon""", """CreateRemoteThread detected:""", """"TargetImage":"""" ]
  Fields = [
    """"UtcTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"Image":"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+))"""",
    """"TargetFilename":"({file_path}({file_parent}[^"]*?[\\\/]+)?({file_name}[^"\\\/]+?(\.({file_ext}\w+))?))"""",
    """"Domain":"(NT AUTHORITY|({domain}[^"]+))""",
    """"AccountName":"(SYSTEM|({user}[^"]+))""",
    """"SourceProcessId":"({pid}\d+)""",
    """"SourceProcessGuid":"({process_guid}[^"]+)""",
    """"TargetProcessId":"({target_pid}\d+)""",
    """"TargetProcessGuid":"({target_process_guid}[^"]+)""",
    """"LogonId":"({logon_id}[^"]+)""",
    """"Hostname":"({host}[^"]+)""",
    """"TargetImage":"({target_process}({target_directory}[^"]*?[\\\/]+)?({target_process_name}[^"\\\/]+))"""",
    """"EventID":({event_code}\d+)""",
    """"SourceImage":"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+))"""",
    """"Category":"({event_name}[^"]+)""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path", "target_process->target_path" ]
}
```