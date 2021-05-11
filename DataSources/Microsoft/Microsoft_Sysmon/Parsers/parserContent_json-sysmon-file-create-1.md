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
    """exabeam_host=({host}[\w.\-]+)""",
    """"Hostname":"{1,20}({host}[^"]+)""",
    """"EventID":({event_code}2)""",
    """({event_name}File creation time changed)""",
    """Message\s{0,100}=\s{0,100}"?({activity_type}[^:]+)""",
    """"Domain":"(NT AUTHORITY|({domain}[^"]+))""",
    """"AccountName":"(SYSTEM|({user}[^"]+))""",
    """"UserID":"({user_sid}[^"]+)""",
    """"Keywords":({outcome}[^,"]+)""",
    """ProcessGuid:\s{0,100}\{({process_guid}[^\s\}]+)""",
    """ProcessId:\s{0,100}({pid}\d{1,100})""",
    """"Image"{1,20}:"{1,20}({process}({process_directory}[^"]+)\\+({process_name}[^"]+))""",
    """"TargetFilename":"({file_path}({file_parent}[^"]+?[\\\/]+)?({file_name}[^"\\\/]+?(\.({file_ext}\w+))?))"""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path" ]
}
```