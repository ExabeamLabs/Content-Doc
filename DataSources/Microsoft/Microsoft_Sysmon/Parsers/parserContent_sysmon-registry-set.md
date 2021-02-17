#### Parser Content
```Java
{
Name = sysmon-registry-set
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Splunk
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """=Microsoft-Windows-Sysmon""", """Message=Registry value set:""" ]
  Fields = [ 
    """UtcTime:\s*({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """\sComputer(?:Name)?=({host}[^\s]+)""",
    """Message=({activity_type}[^:]+)""",
    """Task=({activity}.+?)\s+(\w+=|$)""",
    """User=({user}.+?)\s+(\w+=|$)""",
    """Domain=({domain}.+?)\s+(\w+=|$)""",
    """User:\s*(?:({domain}[^\\]+)\\)?({user}.+?)\s+\w+:""",
    """ProcessGuid:\s*\{({process_guid}[^\s\}]+)""",
    """ProcessId:\s*({pid}\d+)""",
    """\s+Image:\s*({process}({directory}(?:(\w+:)?[^:]+)?[\\\/])?({process_name}.+?))\s+\w+:""",
    """\s+Image:\s*({file_path}({file_parent}(?:(\w+:)?[^:]+)?[\\\/])?({file_name}.+?))\s+\w+:"""
  ]
  DupFields = [ "directory->process_directory", "host->dest_host" ]
}
```