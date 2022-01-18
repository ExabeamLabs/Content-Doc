#### Parser Content
```Java
{
Name = s-adfs-auth-failed
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "authentication-failed"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """SourceName =AD FS""", """EventCode=411""", """Keywords=Audit Failure""" ]
  Fields = [
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (AM|am|PM|pm))""",
    """ComputerName =({host}[\w\-.]{1,2000})""",
    """EventCode=({event_code}\d{1,100})""",
    """Client IP:\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """Error message:\s{0,100}({user}.+?)-The user name""",
    """Error message:\s{0,100}({failure_reason}.+?)\s{1,100}Exception details:"""
  ]


}
```