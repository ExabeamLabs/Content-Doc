#### Parser Content
```Java
{
Name = l-4672
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-privileged-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4672</EventID>", "Special privileges assigned to new logon", "logon.Subject:" ]
  Fields = [
    """({event_name}Special privileges assigned to new logon)""",
    """\WSystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[\w\-\.]+)</Computer>""",
    """<Keywords>({outcome}[^<]+)</Keywords>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """\s*Account Name:\s*({user}.+?)\s*Account Domain:\s*({domain}[^\s]+)\s*Logon ID:""",
    """\s*Logon ID:\s*({logon_id}.+?)\s*Privileges:""",
    """\s*Privileges:\s*({privileges}.+?)</EventData>"""
  ]
  DupFields = [ "host->dest_host" ]
}
```