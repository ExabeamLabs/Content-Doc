#### Parser Content
```Java
{
Name = xml-4739
  Vendor = Microsoft
  Product = Windows
  Lms = Splunk
  DataType = "config-change"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """Domain Policy was changed""", """<EventID>4739<""", """='SubjectUserName'>""" ]
  Fields = [
    """<TimeCreated SystemTime(\\)?='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """<Computer>({host}({dest_host}[^<>]{1,2000}))<""",
    """({event_name}Domain Policy was changed)""",
    """<Execution ProcessID(\\)?='({process_id}[^']{1,2000})""",
    """<EventID>({event_code}\d{1,100})</EventID>""",
    """<Keyword>({outcome}[^<]{1,2000})<""",
    """<Data Name\\?='SubjectUserSid'>({user_sid}[^<]{1,2000})<\/Data>""",
    """ThreadID\\?='({thread_id}\d{1,100})""",
    """<Data Name\\?='SubjectUserName'>({user}[^<]{1,2000})<\/Data>""",
    """<Data Name\\?='SubjectDomainName'>({domain}[^<]{1,2000})<\/Data>""",
    """<Data Name\\?='SubjectLogonId'>({logon_id}[^<]{1,2000})<\/Data>"""
  ]


}
```