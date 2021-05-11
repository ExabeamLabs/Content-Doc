#### Parser Content
```Java
{
Name = sysmon-file-create
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Splunk
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Microsoft-Windows-Sysmon""", """File created:""" ]
  Fields = [ """UtcTime:\s{0,100}({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sComputer(?:Name)?\s{0,100}=\s{0,100}"?({host}[^\s"]+)""",
    """Message\s{0,100}=\s{0,100}"?({activity_type}[^:]+)""",
    """User\s{0,100}=\s{0,100}"(({domain}[^"]+?)[\\\/]+)?({user}[^"\\\/]+)""",
    """ProcessGuid:\s{0,100}\{({process_guid}[^\s\}]+)""",
    """ProcessId:\s{0,100}({pid}\d{1,100})""",
    """ParentProcessGuid:\s{0,100}\{({parent_process_guid}[^\s\}]+)""",
    """\s{1,100}Image:\s{0,100}({process}({directory}(?:(\w+:)?[^:]+)?[\\\/])?({process_name}.+?))\s{1,100}TargetFilename:""",
    """\sTargetFilename:\s{0,100}({file_path}(({file_parent}.+?)[\\\/]+)?({file_name}[^\\\/]*?(\.({file_ext}\w+))?))\s{1,100}CreationUtcTime:""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path" ]
}
```