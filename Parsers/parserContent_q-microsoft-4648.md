#### Parser Content
```Java
{
Name = q-microsoft-4648
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-account-switch"
  TimeFormat = "epoch"
  Conditions = [ "EventIDCode=4648"]
  Fields = [
    """exabeam_endTime=({time}\d+)""",
    """EventIDCode=({event_code}\d+)""",
    """\s+Computer=({host}[\w.\-]+)""",
    """Message=.+?\s({user}[^\s]+)\s({domain}[^\s]+)\s({login_id}[^\s]+)\s\{([^\}]+)\}\s({account}[^\s]+)\s({account_domain}[^\s]+)\s\{"""
  ]
  DupFields = [ "host->dest_host" ]
}
```