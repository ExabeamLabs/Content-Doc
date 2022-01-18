#### Parser Content
```Java
{
Name = sysmon-process-created-1
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Splunk
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Microsoft-Windows-Sysmon""", """CreateRemoteThread detected:""" ]
  Fields = [ 
    """UtcTime:\s{0,100}({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Hostname":"({host}[^"]{1,2000}?)"""",
    """\sComputer(?:Name)?\s{0,100}=\s{0,100}"?({host}[^\s"]{1,2000})""",
    """Message\s{0,100}=\s{0,100}"?({activity_type}[^:]{1,2000})""",
    """User\s{0,100}=\s{0,100}"(({domain}[^"]{1,2000}?)[\\\/]{1,2000})?({user}[^"\\\/]{1,2000})""",
    """SourceProcessGuid:\s{0,100}\{({process_guid}[^\s\}]{1,2000})""",
    """SourceProcessId:\s{0,100}({pid}\d{1,100})""",
    """\s{1,100}SourceImage:\s{0,100}({process}({directory}(?:(\w+:)?[^:]{1,2000})?[\\\/])?({process_name}.+?))\s{1,100}TargetProcessGuid:""",
    """TargetProcessGuid:\s{0,100}\{({target_process_guid}[^\s\}]{1,2000})""",
    """TargetProcessId:\s{0,100}({target_pid}\d{1,100})""",
    """\s{1,100}TargetImage:\s{0,100}({target_process}({target_directory}(?:(\w+:)?[^:]{1,2000})?[\\\/])?({target_process_name}.+?))\s{1,100}NewThreadId:""",
    """EventID":({event_code}\d{1,100}),""",
    """"SourceImage":"({process}(({directory}[^"]{0,2000}?)[\\\/]{1,20})?({process_name}[^"\\\/]{1,2000}))"""",
    """"TargetImage":"({target_process}(({target_directory}[^"]{0,2000}?)[\\\/]{1,20})?({target_process_name}[^"\\\/]{1,2000}))"""",
    """AccountName":"({user}[^"]{1,2000}?)"""",
    """Domain":"({domain}[^"]{1,2000}?)""""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path" ]


}
```