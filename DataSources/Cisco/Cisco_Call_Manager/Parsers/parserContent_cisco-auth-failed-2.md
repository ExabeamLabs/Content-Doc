#### Parser Content
```Java
{
Name = cisco-auth-failed-2
  Vendor = Cisco
  Product = Cisco Call Manager
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "MMM dd yyyy HH:mm:ss a"
  Conditions = [ """EventType =UserLogging""", """EventStatus =Failure""", """Failed to Log into Cisco CCM Webpages""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\s({time}\w+\s+\d+\s+\d+\s+\d+:\d+:\d+\s+(AM|PM|am|pm))""",
    """UserID\s*=({user}[^\s\]]+)""",
    """ClientAddress\s*=({src_ip}[A-Fa-f:\d.]+)""",
    """EventType\s*=({activity}[^\]]+)""",
    """ResourceAccessed\s*=({object}[^\]]+)""",
    """EventStatus\s*=({outcome}[^\]]+)""",
    """ComponentID\s*=({target}[^\]]+)""",
    """AuditDetails\s*=({event_name}[^\]]+)""",
    """Node ID=({dest_host}[^\]]+)""",
    """App ID\s*=({app}[^\]]+)""",
  ]
}
```