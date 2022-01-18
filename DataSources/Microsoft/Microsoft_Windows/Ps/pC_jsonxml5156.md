#### Parser Content
```Java
{
Name = json-xml-5156
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-network"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """"EventID":"5156"""", """<Data Name ='""" ]
  Fields = [
    """({event_name}The Windows Filtering Platform has allowed a connection)""",
    """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({event_code}5156)""",
    """"Computer":"({host}[^"]{1,2000})""",
    """<Data Name ='ProcessID'>({pid}[^<>]{1,2000})<\/Data>""",
    """<Data Name ='Application'>({process}({process_directory}(?:[^<]{1,2000})?[\\\/])?({process_name}[^\\\/]{1,2000}?))<\/Data>""",
    """<Data Name ='SourceAddress'>({src_ip}[a-fA-F:\d.]{1,2000})</Data>""",
    """<Data Name ='SourcePort'>({src_port}\d{1,100})</Data>""",
    """<Data Name ='DestAddress'>({dest_ip}[a-fA-F:\d.]{1,2000})</Data>""",
    """<Data Name ='DestPort'>({dest_port}\d{1,100})</Data>""",
    """<Data Name ='Protocol'>({protocol}[^<>]{1,2000})</Data>""",
    """<Data Name ='Direction'>({direction}[^<>]{1,2000})</Data>""",
    """<Data Name ='LayerName'>({layer_name}[^<>]{1,2000})</Data>""",
    """<RenderingInfo.+?<Task>({activity_type}[^<>]{1,2000})</Task>.*?</RenderingInfo>"""
  ]
  DupFields = [ "host->local_asset" ]


}
```