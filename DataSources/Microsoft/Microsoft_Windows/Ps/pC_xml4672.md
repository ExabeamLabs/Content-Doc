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
    """<Computer>({host}({dest_host}[\w\-]{1,2000})[\w\-\.]{0,2000})</Computer>""",
    """<Keywords>({outcome}[^<]{1,2000})</Keywords>""",
    """<Keywords><Keyword>({outcome}[^<]{1,2000})</Keyword></Keywords>""",
    """<EventID>({event_code}[^<]{1,2000})</EventID>""",
    """<Data Name(\\)?='SubjectLogonId'>({logon_id}[^<]{1,2000})""",
    """<Data Name(\\)?='SubjectUserName'>(SYSTEM|NETWORK SERVICE|({user}[^<]{1,2000}))</Data>""",
    """<Data Name(\\)?='SubjectDomainName'>(?:NT AUTHORITY|({domain}[^<]{1,2000}))</Data>""",
    """<Data Name(\\)?='SubjectLogonId'>({logon_id}[^<]{1,2000})</Data>""",
    """({event_name}Special privileges assigned to new logon)""",
    """<Data Name(\\)?='PrivilegeList'>({privileges}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?='SubjectUserSid'>({user_sid}[^<]{1,2000})</Data>"""
  ]


}
```