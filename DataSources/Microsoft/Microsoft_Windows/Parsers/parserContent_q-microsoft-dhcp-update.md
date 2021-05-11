#### Parser Content
```Java
{
Name = q-microsoft-dhcp-update
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "dhcp"
  TimeFormat = "epoch"
  Conditions = [ "Description=DNS Update Successful", "Host Name=", """QResult=""" ]
  Fields = [
    """<.*?>\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[^\s]+)""",
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+)""",
    """exabeam_endTime=({time}\d{1,100})""",
    """\sIP Address=({dest_ip}[a-fA-F\d.:]+)""",
    """\sHost Name=({dest_host}[\w.\-]+)""",
  ]
  DupFields = [ "dest_host->user" ]
}
```