#### Parser Content
```Java
{
Name = json-xml-5156
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-network"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """"EventID":"5156"""", """<Data Name='""" ]
  Fields = [
    """({event_name}The Windows Filtering Platform has allowed a connection)""",
    """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({event_code}5156)""",
    """"Computer":"({host}[^"]+)""",
    """<Data Name='ProcessID'>({pid}[^<>]+)<\/Data>""",
    """<Data Name='Application'>({process}({process_directory}(?:[^<]+)?[\\\/])?({process_name}[^\\\/]+?))<\/Data>""",
    """<Data Name='SourceAddress'>({src_ip}[a-fA-F:\d.]+)</Data>""",
    """<Data Name='SourcePort'>({src_port}\d+)</Data>""",
    """<Data Name='DestAddress'>({dest_ip}[a-fA-F:\d.]+)</Data>""",
    """<Data Name='DestPort'>({dest_port}\d+)</Data>""",
    """<Data Name='Protocol'>({protocol}[^<>]+)</Data>""",
    """<Data Name='Direction'>({direction}[^<>]+)</Data>""",
    """<Data Name='LayerName'>({layer_name}[^<>]+)</Data>""",
    """<RenderingInfo.+?<Task>({activity_type}[^<>]+)</Task>.*?</RenderingInfo>"""
  ]
  DupFields = [ "host->local_asset" ]
}
```