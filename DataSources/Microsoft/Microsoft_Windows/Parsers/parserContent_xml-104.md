#### Parser Content
```Java
{
Name = xml-104
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-audit"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """<EventID>104<""", """log file was cleared.""" ]
  Fields = [
    """<EventID>({event_code}\d{1,100})""",
    """<Keywords>({outcome}[^<]{1,2000})""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """<Computer>({host}[^<]{1,2000})""",
    """<Security UserID='({user_sid}[^'<\/]{1,2000})""",
    """<SubjectUserName>(SYSTEM|({user}[^<]{1,2000}))""",
    """<SubjectDomainName>(NT AUTHORITY|({domain}[^<]{1,2000}))""",
    """<Message>({event_name}[^<]{1,2000})""",
    """<Level>({alert_severity}[^<]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" ]
}
```