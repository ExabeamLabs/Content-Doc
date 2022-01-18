#### Parser Content
```Java
{
Name = raw-4779
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4779"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["A session was disconnected from a Window Station", "Session Name"]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({event_name}A session was disconnected from a Window Station)""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """({event_code}4779)""",
    """Account Name(:|=)\s{0,100}({user}[^\s;]{1,2000})[\s;]{0,2000}Account Domain(:|=)""",
    """Account Domain(:|=)\s{0,100}({domain}[^\s;]{1,2000})[\s;]{0,2000}Logon ID(:|=)""",
    """Logon ID(:|=)\s{0,100}({logon_id}[^\s;]{1,2000})""",
    """Service Name(:|=)\s{0,100}({dest_host}.+?)[\s;]{0,2000}Service ID""",
    """Client Address(:|=)\s{0,100}(::[\w]{1,2000}:)?(0.0.0.0|({src_ip}[a-fA-F:\d.]{1,2000}))"""
  ]


}
```