#### Parser Content
```Java
{
Name = sysmon-process-created
  Vendor = Microsoft
  Product = Sysmon
  Lms = Splunk
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Microsoft-Windows-Sysmon""", """Process Create:""" ]
  Fields = [ """UtcTime:\s*({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sComputer(?:Name)?\s*=\s*"?({host}[^\s"]+)""",
    """Message\s*=\s*"?({activity_type}[^:]+)""",
    """User=({user}.+?)\s+(\w+=|$)""",
    """Domain=({domain}.+?)\s+(\w+=|$)""",
    """User:\s*(?:({domain}[^\\]+)\\)?({user}.+?)\s+LogonGuid:""",
    """Sid=\s*({user_sid}[^\s]+)""",
    """LogonId:\s*({logon_id}[^\s]+)""",
    """Hashes:.*?,?MD5=({md5}[^\s,]+)""",
    """ProcessGuid:\s*\{({process_guid}[^\s\}]+)""",
    """ProcessId:\s*({pid}\d+)""",
    """ParentProcessGuid:\s*\{({parent_process_guid}[^\s\}]+)""",
    """CommandLine:\s*({command_line}.+?)\s*CurrentDirectory:""",
    """\s+Image:\s*({process}({directory}(?:(\w+:)?[^:]+)?[\\\/])?({process_name}.+?))\s+CommandLine:""",
    """\s+Image:\s*({process}({directory}(?:(\w+:)?[^:]+)?[\\\/])?({process_name}.+?))\s+FileVersion:""",
    """\s+ParentImage:\s*({parent_process}({parent_directory}(?:(\w+:)?[^:]+)?[\\\/])?({parent_process_name}.+?))\s+ParentCommandLine:"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path" ]
}
```