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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\s({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm))""",
    """UserID\s{0,100}=({user}[^\s\]]+)""",
    """ClientAddress\s{0,100}=({src_ip}[A-Fa-f:\d.]+)""",
    """EventType\s{0,100}=({activity}[^\]]+)""",
    """ResourceAccessed\s{0,100}=({object}[^\]]+)""",
    """EventStatus\s{0,100}=({outcome}[^\]]+)""",
    """ComponentID\s{0,100}=({target}[^\]]+)""",
    """AuditDetails\s{0,100}=({event_name}[^\]]+)""",
    """Node ID=({dest_host}[^\]]+)""",
    """App ID\s{0,100}=({app}[^\]]+)""",
  ]
}
```