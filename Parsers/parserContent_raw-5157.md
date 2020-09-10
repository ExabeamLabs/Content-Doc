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
    """\Wrt=({time}\d+)""",
    """({event_name}The Windows Filtering Platform has blocked a connection)""",
    """({event_code}5157)""",
    """ComputerName:\s*({host}[\w.\-]+)""",
    """\sProcess ID:\s*(|({process_id}\d+))\s*Application Name:\s*(|({process}({directory}.*?[\\\/]+)?({process_name}[^\\\/]+?)))\s*Network Information:""",
    """\sDirection:\s*({direction}\S+)""",
    """\sSource Address:\s*({src_ip}[a-fA-F\d.:]+)""",
    """\sSource Port:\s*({src_port}\d+)""",
    """\sDestination Address:\s*({src_ip}[a-fA-F\d.:]+)""",
    """\sDestination Port:\s*({src_port}\d+)""",
    """\sProtocol:\s*({protocol}\S+)""",
    """\sLayer Name:\s*(|({layer_name}.+?))\s*Layer Run-Time ID:""",
    """\sUser:\s*(N/A|({user}.+?))\s*ComputerName:""",
  ]
  DupFields = [ "host->local_asset" ]
}
```