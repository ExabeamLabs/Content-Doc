#### Parser Content
```Java
{
Name = xml-5157
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Exabeam
  DataType = "process-network-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """<EventID>5157</EventID>""", """<Event xmlns='""" ]
  Fields = [
    """({event_name}The Windows Filtering Platform has blocked a connection)""",
    """<TimeCreated SystemTime='({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)\d+Z'/>""",
    """({event_code}5157)""",
    """<Computer>({host}[^<>]+)</Computer>""",
    """<Data Name='ProcessID'>({pid}[^<>]+)<\/Data>""",
    """<Data Name='Application'>({process}({process_directory}(?:[^<]+)?[\\\/])?({process_name}[^\\\/]+?))<\/Data>""",
    """<Data Name='SourceAddress'>({src_ip}[a-fA-F:\d.]+)</Data>""",
    """<Data Name='SourcePort'>({src_port}\d+)</Data>""",
    """<Data Name='DestAddress'>({dest_ip}[a-fA-F:\d.]+)</Data>""",
    """<Data Name='DestPort'>({dest_port}\d+)</Data>""",
    """<Data Name='Protocol'>({protocol}[^<>]+)</Data>""",
    """<RenderingInfo.+?<Task>({activity_type}[^<>]+)</Task>.*?</RenderingInfo>""",
    """<Computer>({src_host}[^<>]+)</Computer>.+?Direction:\s*({direction}Outbound)""",
    """<Computer>({dest_host}[^<>]+)</Computer>.+?Direction:\s*({direction}Inbound)""",
    """Layer Name:\s*({layer_name}[^\s]+)"""
  ]
  DupFields = [ "host->local_asset" ]
}
```