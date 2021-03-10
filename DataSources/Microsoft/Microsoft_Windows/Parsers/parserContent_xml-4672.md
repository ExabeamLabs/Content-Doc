#### Parser Content
```Java
{
Name = xml-4672
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-privileged-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4672</EventID>", "<Data Name='SubjectUserName'>" ]
  Fields = [
    """\WSystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[\w\-\.]+)</Computer>""",
    """<Keywords>({outcome}[^<]+)</Keywords>""",
    """<Keywords><Keyword>({outcome}[^<]+)</Keyword></Keywords>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """Account Name:\s*(SYSTEM|({user}\S+))\s*Account Domain:\s*({domain}.+?)\s*Logon ID:""",
    """Logon ID:\s*({logon_id}.+?)\s*Privileges:""",
    """Privileges:\s*({privileges}.+?)</Message>""",
    """<Data Name='SubjectUserName'>(SYSTEM|({user}[^<]+))</Data>""",
    """<Data Name='SubjectDomainName'>({domain}[^<]+)</Data>""",
    """<Data Name='SubjectLogonId'>({logon_id}[^<]+)</Data>""",
    """<Data Name='PrivilegeList'>({privileges}[^<]+)</Data>"""
  ]
  DupFields = [ "host->dest_host" ]
}
```