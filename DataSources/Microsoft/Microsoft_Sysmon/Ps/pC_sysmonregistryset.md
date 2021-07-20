#### Parser Content
```Java
{
Name = sysmon-registry-set
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Splunk
  DataType = "registry-write"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """=Microsoft-Windows-Sysmon""", """Message=Registry value set:""" ]
  Fields = [ 
    """UtcTime:\s{0,100}({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """\sComputer(?:Name)?=({host}[^\s]{1,2000})""",
    """Message=({activity_type}[^:]{1,2000})""",
    """Task=({activity}.+?)\s{1,100}(\w+=|$)""",
    """User=({user}.+?)\s{1,100}(\w+=|$)""",
    """Domain=({domain}.+?)\s{1,100}(\w+=|$)""",
    """User:\s{0,100}(?:({domain}[^\\]{1,2000})\\)?({user}.+?)\s{1,100}\w+:""",
    """ProcessGuid:\s{0,100}\{({process_guid}[^\s\}]{1,2000})""",
    """ProcessId:\s{0,100}({process_id}\d{1,100})""",
    """\s{1,100}Image:\s{0,100}({process}({process_directory}(?:(\w+:)?[^:]{1,2000})?[\\\/])?({process_name}.+?))\s{1,100}\w+:""",
    """\s{1,100}Image:\s{0,100}({file_path}({file_parent}(?:(\w+:)?[^:]{1,2000})?[\\\/])?({file_name}.+?))\s{1,100}\w+:"""
  ]
  DupFields = [ "directory->process_directory", "host->dest_host" ]
}
```