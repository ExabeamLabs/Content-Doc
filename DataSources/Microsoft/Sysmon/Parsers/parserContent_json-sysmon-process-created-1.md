#### Parser Content
```Java
{
Name = json-sysmon-process-created-1
  Vendor = Microsoft
  Product = Sysmon
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Microsoft-Windows-Sysmon""", """CreateRemoteThread detected:""", """"TargetImage":"""" ]
  Fields = [
    """"UtcTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"Image":"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+))"""",
    """"TargetFilename":"({file_path}({file_parent}[^"]*?[\\\/]+)?({file_name}[^"\\\/]+?(\.({file_ext}\w+))?))"""",
    """"Domain":"({domain}[^"]+)""",
    """"AccountName":"({user}[^"]+)""",
    """"SourceProcessId":"({pid}\d+)""",
    """"SourceProcessGuid":"({process_guid}[^"]+)""",
    """"TargetProcessId":"({target_pid}\d+)""",
    """"TargetProcessGuid":"({target_process_guid}[^"]+)""",
    """"LogonId":"({logon_id}[^"]+)""",
    """"Hostname":"({host}[^"]+)""",
    """"TargetImage":"({target_process}({target_directory}[^"]*?[\\\/]+)?({target_process_name}[^"\\\/]+))"""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path" ]
}
```