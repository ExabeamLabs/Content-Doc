#### Parser Content
```Java
{
Name = json-xml-5158
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-network-bind"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """5158""", """<Data Name='""", """The Windows Filtering Platform has permitted a bind to a local port""" ]
  Fields = [
    """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({event_code}5158)""",
    """"Activity":"({event_name}[^"]{1,2000})""",
    """"Computer":"({host}[^"]{1,2000})""",
    """<Data Name='ProcessId'>({pid}.+?)</Data>""",
    """<Data Name='Application'>({process}({directory}[^<>]{0,2000}?[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000}))</Data>""",
    """<Data Name='SourceAddress'>(0\.0\.0\.0|({dest_ip}[a-fA-F:\d.]{1,2000}))</Data>""",
    """<Data Name='SourcePort'>({dest_port}\d{1,100})""",
    """<Data Name='Protocol'>({ms_protocol_num}.+?)</Data>""",
    """<Data Name='LayerName'>({layer_name}.+?)</Data>""",
  ]
  DupFields = [ "host->dest_host" ]
}
```