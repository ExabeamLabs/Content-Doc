#### Parser Content
```Java
{
Name = json-sysmon-file-create-1
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Splunk
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """File creation time changed:""", """Microsoft-Windows-Sysmon""", """EventID":2""" ]
  Fields = [
    """"EventTime":"({time}\d{1,100}-\d{1,100}-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"Hostname":"{1,20}({host}[^"]{1,2000})""",
    """"EventID":({event_code}2)""",
    """({event_name}File creation time changed)""",
    """Message\s{0,100}=\s{0,100}"?({activity_type}[^:]{1,2000})""",
    """"Domain":"(NT AUTHORITY|({domain}[^"]{1,2000}))""",
    """"AccountName":"(SYSTEM|({user}[^"]{1,2000}))""",
    """"UserID":"({user_sid}[^"]{1,2000})""",
    """"Keywords":({outcome}[^,"]{1,2000})""",
    """ProcessGuid:\s{0,100}\{({process_guid}[^\s\}]{1,2000})""",
    """ProcessId:\s{0,100}({pid}\d{1,100})""",
    """"Image"{1,20}:"{1,20}({process}({process_directory}[^"]{1,2000})\\+({process_name}[^"]{1,2000}))""",
    """"TargetFilename":"({file_path}({file_parent}[^"]{1,2000}?[\\\/]{1,2000})?({file_name}[^"\\\/]{1,2000}?(\.({file_ext}\w+))?))"""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path" ]


}
```