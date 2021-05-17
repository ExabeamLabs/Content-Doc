#### Parser Content
```Java
{
Name = l-4740
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-lockout"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>4740</EventID>""", """A user account was locked out""" ]
  Fields = [
    """({event_name}A user account was locked out)""",
    """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """<EventID>({event_code}[^<]{1,2000})</EventID>""",
    """Subject:[^=]{1,2000}?Account Name:\s{0,100}({caller_user}[^:]{1,2000}?)\s{0,100}Account Domain:\s{0,100}(?=\w)({caller_domain}[^:]{1,2000}?)\s{0,100}Logon ID:\s{0,100}({logon_id}[^:]{1,2000}?)\s{0,100}Account That Was""",
    """Account That Was Locked Out:\s{0,100}Security ID:\s{0,100}({user_sid}[^:]{1,2000}?)\s{0,100}Account Name:\s{0,100}({user}[^:]{1,2000}?)\s{0,100}Additional""",
    """Caller Computer Name:\s{0,100}(?:\\+)?({src_host}[\w-\.]{1,2000})""",
    """<Data Name='TargetUserName'>({user}[^<]{1,2000})<""",
    """<Data Name='TargetSid'>({user_sid}[^<]{1,2000})<""",
    """<Data Name='SubjectUserName'>({caller_user}[^<]{1,2000})<""",
    """<Data Name='SubjectDomainName'>({caller_domain}[^<]{1,2000})<""",
    """<Data Name='SubjectLogonId'>({logon_id}[^<]{1,2000})<""",
    """<Data Name='TargetDomainName'>(?:\\+)?({src_host}[^<=\s]{1,2000})(<|\s)"""
  ]
  DupFields = [ "host->dest_host","caller_domain->domain" ]
}
```