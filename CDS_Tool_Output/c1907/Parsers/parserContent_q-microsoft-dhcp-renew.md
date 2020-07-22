#### Parser Content
```Java
{
Name = q-microsoft-dhcp-renew
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "dhcp"
  TimeFormat = "epoch"
  Conditions = [ "Description=Renew", "Host Name=", "QResult=" ]
  Fields = [
    """<.*?>\w+ \d+ \d+:\d+:\d+\s+({host}[^\s]+)""",
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """exabeam_startTime=({time}\d+)""",
    """\sIP Address=({dest_ip}[a-fA-F\d.:]+)""",
    """\sHost Name=({dest_host}[\w.\-]+)""",
  ]
  DupFields = [ "dest_host->user" ]
}
```