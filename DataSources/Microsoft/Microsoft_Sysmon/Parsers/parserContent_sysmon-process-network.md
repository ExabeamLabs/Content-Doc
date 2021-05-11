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
    """\sComputer(?:Name)?\s{0,100}=\s{0,100}"?({host}[^\s"]+)""",
    """Computer>({host}[^<]+)<\/Computer""",
    """Message\s{0,100}=\s{0,100}"?({activity_type}[^:]+)""",
    """Task="{0,20}({activity}[^=]+?)"{0,20}\s{1,100}(\w+=|$)""",
    """User=({user}[^=]+?)\s{1,100}(\w+=|$)""",
    """Domain=({domain}[^=]+?)\s{1,100}(\w+=|$)""",
    """User:\s{0,100}(?:({domain}[^\\]+)\\+)?({user}[^:]+?)\s{1,100}\w+:""",
    """Protocol:\s{0,100}({protocol}[^\s]+)""",
    """ProcessGuid:\s{0,100}\{({process_guid}[^\s\}]+)""",
    """ProcessId:\s{0,100}({pid}\d{1,100})""",
    """\s{1,100}Image:\s{0,100}({process}({directory}(?:(\w+:)?[^:]+)?[\\\/])?({process_name}[^:]+?))\s{1,100}\w+:""",
    """SourceIp:\s{0,100}({src_ip}[a-fA-F0-9.:]+)""",
    """SourceHostname:\s{0,100}({src_host}[^\s]+?)\s{0,100}(Source|$)""",
    """SourcePort:\s{0,100}({src_port}\d{1,100})""",
    """DestinationIp:\s{0,100}({dest_ip}[a-fA-F0-9.:]+)""",
    """DestinationHostname:\s{0,100}({dest_host}[^\s]+?)\s{0,100}(Destination|$)""",
    """DestinationPort:\s{0,100}({dest_port}\d{1,100})""",
    """\sInitiated:\s{0,100}({initiated}[^\s]+)"""
  ]
  DupFields = [ "directory->process_directory" ]
}
```