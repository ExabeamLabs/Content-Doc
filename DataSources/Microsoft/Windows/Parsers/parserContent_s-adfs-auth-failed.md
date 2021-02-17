#### Parser Content
```Java
{
Name = s-adfs-auth-failed
  Vendor = Microsoft
  Product = Windows
  Lms = Splunk
  DataType = "authentication-failed"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """SourceName=AD FS""", """EventCode=411""", """Keywords=Audit Failure""" ]
  Fields = [
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (AM|am|PM|pm))""",
    """ComputerName=({host}[\w\-.]+)""",
    """EventCode=({event_code}\d+)""",
    """Client IP:\s*({src_ip}[A-Fa-f:\d.]+)""",
    """Error message:\s*({user}.+?)-The user name""",
    """Error message:\s*({failure_reason}.+?)\s+Exception details:"""
  ]
}
```