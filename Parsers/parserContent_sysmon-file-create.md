#### Parser Content
```Java
{
Name = sysmon-file-create
  Vendor = Microsoft
  Product = Sysmon
  Lms = Splunk
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Microsoft-Windows-Sysmon""", """File created:""" ]
  Fields = [ """UtcTime:\s*({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sComputer(?:Name)?\s*=\s*"?({host}[^\s"]+)""",
    """Message\s*=\s*"?({activity_type}[^:]+)""",
    """User\s*=\s*"(({domain}[^"]+?)[\\\/]+)?({user}[^"\\\/]+)""",
    """ProcessGuid:\s*\{({process_guid}[^\s\}]+)""",
    """ProcessId:\s*({pid}\d+)""",
    """ParentProcessGuid:\s*\{({parent_process_guid}[^\s\}]+)""",
    """\s+Image:\s*({process}({directory}(?:(\w+:)?[^:]+)?[\\\/])?({process_name}.+?))\s+TargetFilename:""",
    """\sTargetFilename:\s*({file_path}(({file_parent}.+?)[\\\/]+)?({file_name}[^\\\/]*?(\.({file_ext}\w+))?))\s+CreationUtcTime:""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path" ]
}
```