#### Parser Content
```Java
{
Name = raw-sysmon-process-network
  Vendor = Microsoft
  Product = Sysmon
  Lms = Direct
  DataType = "process-network"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """<Provider Name='Microsoft-Windows-Sysmon'""", """<EventID>3</EventID>""" ]
  Fields = [
    """<Provider Name='Microsoft-Windows-Sysmon' Guid='\{({process_guid}[^}]+?)\}""",
    """<EventID>({event_id}\d+)</EventID>""",
    """<Task>({activity}.*?)</Task>""",
    """<Execution ProcessID='({pid}\d+)""",
    """UtcTime:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """<Computer>({host}.+?)</Computer>""",
    """<Security UserID='(({domain}[^\\>]+?)\\)?({user}.+?)'\s*/>""",
    """<EventData>.*?Image:\s*({process}({directory}.*?)({process_name}[^.\\]+\.exe))\s*User:""",
    """<EventData>.*?Image:\s*({path}.+?)\s*User:""",
    """SourceIp:\s*({src_ip}[a-fA-F0-9.:]+)""",
    """SourceHostname:\s*({src_host}.*?)\s*(Source|$)""",
    """<EventData>.*?<Data Name='UtcTime'>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """<EventData>.*?<Data Name='ProcessGuid'>\{({process_guid}[^}]+)\}</Data>""",
    """<EventData>.*?<Data Name='ProcessId'>({pid}\d+)""",
    """<EventData>.*?<Data Name='Image'>({process}({directory}(?:[^<>]+)?[\\\/]+)?({process_name}[^\\\/<>]+))</Data>""",
    """<EventData>.*?<Data Name='User'>(({domain}[^\\>]+?)\\)?({user}[^<>]+)</Data>""",
    """<EventData>.*?<Data Name='Protocol'>({protocol}[^<>]+)</Data>""",
    """<EventData>.*?<Data Name='Initiated'>true</Data>.*?<Data Name='SourceIp'>({src_ip}[\da-fA-F\.:]+)""",
    """<EventData>.*?<Data Name='Initiated'>true</Data>.*?<Data Name='SourceHostname'>({src_host}[^<>]+)</Data>""",
    """<EventData>.*?<Data Name='Initiated'>true</Data>.*?<Data Name='SourcePort'>({src_port}\d+)""",
    """<EventData>.*?<Data Name='Initiated'>true</Data>.*?<Data Name='DestinationIp'>({dest_ip}[\da-fA-F\.:]+)""",
    """<EventData>.*?<Data Name='Initiated'>true</Data>.*?<Data Name='DestinationHostname'>({dest_host}[^<>]+)</Data>""",
    """<EventData>.*?<Data Name='Initiated'>true</Data>.*?<Data Name='DestinationPort'>({dest_port}\d+)""",
    """<EventData>.*?<Data Name='Initiated'>false</Data>.*?<Data Name='DestinationIp'>({src_ip}[\da-fA-F\.:]+)""",
    """<EventData>.*?<Data Name='Initiated'>false</Data>.*?<Data Name='DestinationHostname'>({src_host}[^<>]+)</Data>""",
    """<EventData>.*?<Data Name='Initiated'>false</Data>.*?<Data Name='DestinationPort'>({src_port}\d+)""",
    """<EventData>.*?<Data Name='Initiated'>false</Data>.*?<Data Name='SourceIp'>({dest_ip}[\da-fA-F\.:]+)""",
    """<EventData>.*?<Data Name='Initiated'>false</Data>.*?<Data Name='SourceHostname'>({dest_host}[^<>]+)</Data>""",
    """<EventData>.*?<Data Name='Initiated'>false</Data>.*?<Data Name='SourcePort'>({dest_port}\d+)"""
  ]
  DupFields = ["directory->process_directory"]
}
```