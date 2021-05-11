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
    """\s{0,100}Account Name:\s{0,100}({user}.+?)\s{0,100}Account Domain:\s{0,100}({domain}[^\s]+)\s{0,100}Logon ID:""",
    """\s{0,100}Logon ID:\s{0,100}({logon_id}.+?)\s{0,100}Privileges:""",
    """\s{0,100}Privileges:\s{0,100}({privileges}.+?)</EventData>"""
  ]
  DupFields = [ "host->dest_host" ]
}
```