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
    """<Computer>({host}({dest_host}[\w\-]+)[\w\-\.]*)</Computer>""",
    """<Keywords>({outcome}[^<]+)</Keywords>""",
    """<Keywords><Keyword>({outcome}[^<]+)</Keyword></Keywords>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """<Data Name(\\)?='SubjectLogonId'>({logon_id}[^<]+)""",
    """<Data Name(\\)?='SubjectUserName'>(SYSTEM|NETWORK SERVICE|({user}[^<]+))</Data>""",
    """<Data Name(\\)?='SubjectDomainName'>(?:NT AUTHORITY|({domain}[^<]+))</Data>""",
    """<Data Name(\\)?='SubjectLogonId'>({logon_id}[^<]+)</Data>""",
    """({event_name}Special privileges assigned to new logon)""",
    """<Data Name(\\)?='PrivilegeList'>({privileges}[^<]+)</Data>""",
    """<Data Name(\\)?='SubjectUserSid'>({user_sid}[^<\\]+)</Data>"""
  ]
}
```