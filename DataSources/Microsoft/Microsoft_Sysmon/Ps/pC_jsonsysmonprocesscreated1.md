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
    """"Image":"({process}({directory}[^"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000}))"""",
    """"TargetFilename":"({file_path}({file_parent}[^"]{0,2000}?[\\\/]{1,2000})?({file_name}[^"\\\/]{1,2000}?(\.({file_ext}\w+))?))"""",
    """"Domain":"(NT AUTHORITY|({domain}[^"]{1,2000}))""",
    """"AccountName":"(SYSTEM|({user}[^"]{1,2000}))""",
    """"SourceProcessId":"({pid}\d{1,100})""",
    """"SourceProcessGuid":"({process_guid}[^"]{1,2000})""",
    """"TargetProcessId":"({target_pid}\d{1,100})""",
    """"TargetProcessGuid":"({target_process_guid}[^"]{1,2000})""",
    """"LogonId":"({logon_id}[^"]{1,2000})""",
    """"Hostname":"({host}[^"]{1,2000})""",
    """"TargetImage":"({target_process}({target_directory}[^"]{0,2000}?[\\\/]{1,2000})?({target_process_name}[^"\\\/]{1,2000}))"""",
    """"EventID":({event_code}\d{1,100})""",
    """"SourceImage":"({process}({directory}[^"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000}))"""",
    """"Category":"({event_name}[^"]{1,2000})""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path", "target_process->target_path" ]


}
```