#### Parser Content
```Java
{
Name = sysmon-process-network
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Splunk
  DataType = "process-network"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """Microsoft-Windows-Sysmon""", """Network connection detected:""" ]
  Fields = [ 
    """UtcTime:\s{0,100}({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """\sComputer(?:Name)?\s{0,100}=\s{0,100}"?({host}[^\s"]{1,2000})""",
    """Computer>({host}[^<]{1,2000})<\/Computer""",
    """Message\s{0,100}=\s{0,100}"?({activity_type}[^:]{1,2000})""",
    """Task="{0,20}({activity}[^=]{1,2000}?)"{0,20}\s{1,100}(\w+=|$)""",
    """User=({user}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """Domain=({domain}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """User:\s{0,100}(?:({domain}[^\\]{1,2000})\\+)?({user}[^:]{1,2000}?)\s{1,100}\w+:""",
    """Protocol:\s{0,100}({protocol}[^\s]{1,2000})""",
    """ProcessGuid:\s{0,100}\{({process_guid}[^\s\}]{1,2000})""",
    """ProcessId:\s{0,100}({pid}\d{1,100})""",
    """\s{1,100}Image:\s{0,100}({process}({directory}(?:(\w+:)?[^:]{1,2000})?[\\\/])?({process_name}[^:]{1,2000}?))\s{1,100}\w+:""",
    """SourceIp:\s{0,100}({src_ip}[a-fA-F0-9.:]{1,2000})""",
    """SourceHostname:\s{0,100}({src_host}[^\s]{1,2000}?)\s{0,100}(Source|$)""",
    """SourcePort:\s{0,100}({src_port}\d{1,100})""",
    """DestinationIp:\s{0,100}({dest_ip}[a-fA-F0-9.:]{1,2000})""",
    """DestinationHostname:\s{0,100}({dest_host}[^\s]{1,2000}?)\s{0,100}(Destination|$)""",
    """DestinationPort:\s{0,100}({dest_port}\d{1,100})""",
    """\sInitiated:\s{0,100}({initiated}[^\s]{1,2000})"""
  ]
  DupFields = [ "directory->process_directory" ]
}
```