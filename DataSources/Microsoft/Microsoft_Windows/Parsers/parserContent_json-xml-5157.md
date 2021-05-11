#### Parser Content
```Java
{
Name = json-xml-5157
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-network-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
    Conditions = [ """"EventID":"5157"""", """<Data Name='""" ]
  Fields = [
    """({event_name}The Windows Filtering Platform has blocked a connection)""",
      """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({event_code}5157)""",
    """"Computer":"({host}[^"]+)""",
    """<Data Name='ProcessID'>({pid}[^<>]+)<\/Data>""",
    """<Data Name='Application'>({process}({process_directory}(?:[^<]+)?[\\\/])?({process_name}[^\\\/]+?))<\/Data>""",
    """<Data Name='SourceAddress'>({src_ip}[a-fA-F:\d.]+)</Data>""",
    """<Data Name='SourcePort'>(0|({src_port}\d{1,100}))</Data>""",
    """<Data Name='DestAddress'>({dest_ip}[a-fA-F:\d.]+)</Data>""",
    """<Data Name='DestPort'>(0|({dest_port}\d{1,100}))</Data>""",
    """<Data Name='Protocol'>({protocol}[^<>]+)</Data>""",
    """<RenderingInfo.+?<Task>({activity_type}[^<>]+)</Task>.*?</RenderingInfo>""",
    """<Data Name='Direction'>({direction}[^<>]+)</Data>""",
    """<Data Name='LayerName'>({layer_name}[^<>]+)</Data>"""
  ]
  DupFields = [ "host->local_asset" ]
}
```