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
    """<Keywords>({outcome}[^<]+)""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """<Computer>({host}[^<]+)""",
    """<Security UserID='({user_sid}[^'<\/]+)""",
    """<SubjectUserName>(SYSTEM|({user}[^<]+))""",
    """<SubjectDomainName>(NT AUTHORITY|({domain}[^<]+))""",
    """<Message>({event_name}[^<]+)""",
    """<Level>({alert_severity}[^<]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```