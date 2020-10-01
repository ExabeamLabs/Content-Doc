#### Parser Content
```Java
{
Name = sysmon-process-network
  Vendor = Microsoft
  Product = Sysmon
  Lms = Splunk
  DataType = "process-network"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """Microsoft-Windows-Sysmon""", """Network connection detected:""" ]
  Fields = [ 
    """UtcTime:\s*({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """\sComputer(?:Name)?\s*=\s*"?({host}[^\s"]+)""",
    """Computer>({host}[^<]+)<\/Computer""",
    """Message\s*=\s*"?({activity_type}[^:]+)""",
    """Task=({activity}.+?)\s+(\w+=|$)""",
    """User=({user}.+?)\s+(\w+=|$)""",
    """Domain=({domain}.+?)\s+(\w+=|$)""",
    """User:\s*(?:({domain}[^\\]+)\\)?({user}.+?)\s+\w+:""",
    """Protocol:\s*({protocol}[^\s]+)""",
    """ProcessGuid:\s*\{({process_guid}[^\s\}]+)""",
    """ProcessId:\s*({pid}\d+)""",
    """\s+Image:\s*({process}({directory}(?:(\w+:)?[^:]+)?[\\\/])?({process_name}.+?))\s+\w+:""",
    """SourceIp:\s*({src_ip}[a-fA-F0-9.:]+)""",
    """SourceHostname:\s*({src_host}.*?)\s*(Source|$)""",
    """SourcePort:\s*({src_port}\d+)""",
    """DestinationIp:\s*({dest_ip}[a-fA-F0-9.:]+)""",
    """DestinationHostname:\s*({dest_host}.*?)\s*(Destination|$)""",
    """DestinationPort:\s*({dest_port}\d+)""",
    """\sInitiated:\s*({initiated}[^\s]+)"""
  ]
  DupFields = [ "directory->process_directory" ]
}
```