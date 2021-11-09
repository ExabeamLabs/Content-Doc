#### Parser Content
```Java
{
Name = xml-5144
  Vendor = Microsoft
  Product = Windows
  Lms = ArcSight
  DataType = "share-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """<EventID>5144</EventID>""", """Microsoft-Windows-Security-Auditing""", """<Data Name=""", """A network share object was deleted""" ] 
  Fields = [
    """<TimeCreated SystemTime=('|")({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,10}Z)""",
    """({event_name}A network share object was deleted)""",
    """<Computer>({host}({dest_host}[\w\-]{1,2000})[^<]{0,2000})</Computer>""",
    """<EventID>({event_code}5144)</EventID>""",
    """<Data Name='ShareName'>[\\*]{1,100}({share_name}[^<]{1,2000})<\/Data>""",
    """<Data Name='SubjectDomainName'>({domain}[^<]{1,2000})<\/Data>""",
    """<Data Name='ShareLocalPath'>({share_path}[^<]{1,2000})<\/Data>""",
    """<Data Name='SubjectLogonId'>({logon_id}[^<]{1,2000})<\/Data>""",
    """<Keyword>({outcome}[^<]{1,2000})<\/Keyword>""",
    """<Data Name='SubjectUserName'>({user}[^<]{1,2000})<\/Data>"""
  ]
}
}
```