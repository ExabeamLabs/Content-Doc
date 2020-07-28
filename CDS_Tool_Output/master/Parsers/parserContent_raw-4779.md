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
    """<Computer>({host}[^<]+)</Computer>""",
    """({event_code}4779)""",
    """Account Name(:|=)\s*({user}[^\s;]+)[\s;]*Account Domain(:|=)""",
    """Account Domain(:|=)\s*({domain}[^\s;]+)[\s;]*Logon ID(:|=)""",
    """Logon ID(:|=)\s*({logon_id}[^\s;]+)""",
    """Service Name(:|=)\s*({dest_host}.+?)[\s;]*Service ID""",
    """Client Address(:|=)\s*(::[\w]+:)?(0.0.0.0|({src_ip}[a-fA-F:\d.]+))"""
  ]
}
```