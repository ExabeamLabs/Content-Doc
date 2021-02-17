#### Parser Content
```Java
{
Name = xml-1102-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-audit"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = ["""<EventID>1102""", """LogFileCleared""" ]
  Fields = [
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d\d\d\d\d\d\dZ)""",
    """<Computer>({host}[^<]+)""",
    """<SubjectLogonId>({logon_id}[^<]+)""",
    """({event_code}1102)""",
    """({event_name}LogFileCleared)""",
    """<SubjectUserName>({user}[^<]+)""",
    """<SubjectUserSid>({user_sid}[^<]+)""",
    """<SubjectDomainName>({domain}[^<]+)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```