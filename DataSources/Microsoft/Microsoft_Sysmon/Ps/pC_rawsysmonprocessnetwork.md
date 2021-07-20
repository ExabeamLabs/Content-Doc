#### Parser Content
```Java
{
Name = raw-sysmon-process-network
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Direct
  DataType = "process-network"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """<Provider Name='Microsoft-Windows-Sysmon'""", """<EventID>3</EventID>""" ]
  Fields = [
    """<Provider Name='Microsoft-Windows-Sysmon' Guid='\{({process_guid}[^}]{1,2000}?)\}""",
    """<EventID>({event_code}\d{1,100})</EventID>""",
    """<Task>({activity}.*?)</Task>""",
    """<Execution ProcessID='({pid}\d{1,100})""",
    """UtcTime:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """<Computer>({host}.+?)</Computer>""",
    """<Security UserID='(({domain}[^\\>]{1,2000}?)\\)?({user}.+?)'\s{0,100}/>""",
    """<EventData>.*?Image:\s{0,100}({process}({directory}.*?)({process_name}[^.\\]{1,2000}\.exe))\s{0,100}User:""",
    """<EventData>.*?Image:\s{0,100}({path}.+?)\s{0,100}User:""",
    """SourceIp:\s{0,100}({src_ip}[a-fA-F0-9.:]{1,2000})""",
    """SourceHostname:\s{0,100}({src_host}.*?)\s{0,100}(Source|$)""",
    """<EventData>.*?<Data Name='UtcTime'>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """<EventData>.*?<Data Name='ProcessGuid'>\{({process_guid}[^}]{1,2000})\}</Data>""",
    """<EventData>.*?<Data Name='ProcessId'>({pid}\d{1,100})""",
    """<EventData>.*?<Data Name='Image'>({process}({directory}(?:[^<>]{1,2000})?[\\\/]{1,2000})?({process_name}[^\\\/<>]{1,2000}))</Data>""",
    """<EventData>.*?<Data Name='User'>(({domain}[^\\>]{1,2000}?)\\)?({user}[^<>]{1,2000})</Data>""",
    """<EventData>.*?<Data Name='Protocol'>({protocol}[^<>]{1,2000})</Data>""",
    """<EventData>.*?<Data Name='Initiated'>true</Data>.*?<Data Name='SourceIp'>({src_ip}[\da-fA-F\.:]{1,2000})""",
    """<EventData>.*?<Data Name='Initiated'>true</Data>.*?<Data Name='SourceHostname'>({src_host}[^<>]{1,2000})</Data>""",
    """<EventData>.*?<Data Name='Initiated'>true</Data>.*?<Data Name='SourcePort'>({src_port}\d{1,100})""",
    """<EventData>.*?<Data Name='Initiated'>true</Data>.*?<Data Name='DestinationIp'>({dest_ip}[\da-fA-F\.:]{1,2000})""",
    """<EventData>.*?<Data Name='Initiated'>true</Data>.*?<Data Name='DestinationHostname'>({dest_host}[^<>]{1,2000})</Data>""",
    """<EventData>.*?<Data Name='Initiated'>true</Data>.*?<Data Name='DestinationPort'>({dest_port}\d{1,100})""",
    """<EventData>.*?<Data Name='Initiated'>false</Data>.*?<Data Name='DestinationIp'>({src_ip}[\da-fA-F\.:]{1,2000})""",
    """<EventData>.*?<Data Name='Initiated'>false</Data>.*?<Data Name='DestinationHostname'>({src_host}[^<>]{1,2000})</Data>""",
    """<EventData>.*?<Data Name='Initiated'>false</Data>.*?<Data Name='DestinationPort'>({src_port}\d{1,100})""",
    """<EventData>.*?<Data Name='Initiated'>false</Data>.*?<Data Name='SourceIp'>({dest_ip}[\da-fA-F\.:]{1,2000})""",
    """<EventData>.*?<Data Name='Initiated'>false</Data>.*?<Data Name='SourceHostname'>({dest_host}[^<>]{1,2000})</Data>""",
    """<EventData>.*?<Data Name='Initiated'>false</Data>.*?<Data Name='SourcePort'>({dest_port}\d{1,100})"""
  ]
  DupFields = ["directory->process_directory"]
}
```