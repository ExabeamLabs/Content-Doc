#### Parser Content
```Java
{
Name = raw-5157
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-network-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
    Conditions = [ """5157""", """The Windows Filtering Platform has blocked a connection""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """({event_name}The Windows Filtering Platform has blocked a connection)""",
    """({event_code}5157)""",
    """ComputerName:\s{0,100}({host}[\w.\-]{1,2000})""",
    """\sProcess ID:\s{0,100}(|({process_id}\d{1,100}))\s{0,100}Application Name:\s{0,100}(|({process}({directory}.*?[\\\/]{1,2000})?({process_name}[^\\\/]{1,2000}?)))\s{0,100}Network Information:""",
    """\sDirection:\s{0,100}({direction}\S+)""",
    """\sSource Address:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sSource Port:\s{0,100}({src_port}\d{1,100})""",
    """\sDestination Address:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sDestination Port:\s{0,100}({src_port}\d{1,100})""",
    """\sProtocol:\s{0,100}({protocol}\S+)""",
    """\sLayer Name:\s{0,100}(|({layer_name}.+?))\s{0,100}Layer Run-Time ID:""",
    """\sUser:\s{0,100}(N/A|({user}.+?))\s{0,100}ComputerName:""",
  ]
  DupFields = [ "host->local_asset" ]


}
```