#### Parser Content
```Java
{
Name = xml-4672
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-privileged-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>4672</EventID>""", """'SubjectUserName'>""" ]
  Fields = [    
    """<TimeCreated SystemTime(\\)?='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[\w\-\.]+)</Computer>""",
    """<Keywords>({outcome}[^<]+)</Keywords>""",
    """<Keywords><Keyword>({outcome}[^<]+)</Keyword></Keywords>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """<Data Name(\\)?='SubjectDomainName'>({domain}[^<]+)""",
    """<Data Name(\\)?='SubjectLogonId'>({logon_id}[^<]+)""",
    """<Data Name(\\)?='SubjectUserName'>(SYSTEM|({user}[^<]+))</Data>""",
    """<Data Name(\\)?='SubjectDomainName'>({domain}[^<]+)</Data>""",
    """<Data Name(\\)?='SubjectLogonId'>({logon_id}[^<]+)</Data>""",
  ]
  DupFields = [ "host->dest_host" ]
}
```