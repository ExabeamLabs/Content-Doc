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
    """\sComputer(?:Name)?\s{0,100}=\s{0,100}"?({host}[^\s"]{1,2000})""",
    """Message\s{0,100}=\s{0,100}"?({activity_type}[^:]{1,2000})""",
    """User\s{0,100}=\s{0,100}"(({domain}[^"]{1,2000}?)[\\\/]{1,2000})?({user}[^"\\\/]{1,2000})""",
    """ProcessGuid:\s{0,100}\{({process_guid}[^\s\}]{1,2000})""",
    """ProcessId:\s{0,100}({pid}\d{1,100})""",
    """ParentProcessGuid:\s{0,100}\{({parent_process_guid}[^\s\}]{1,2000})""",
    """\s{1,100}Image:\s{0,100}({process}({directory}(?:(\w+:)?[^:]{1,2000})?[\\\/])?({process_name}.+?))\s{1,100}TargetFilename:""",
    """\sTargetFilename:\s{0,100}({file_path}(({file_parent}.+?)[\\\/]{1,2000})?({file_name}[^\\\/]{0,2000}?(\.({file_ext}\w+))?))\s{1,100}CreationUtcTime:""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path" ]


}
```