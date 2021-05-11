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
    """<Computer>({host}[^<]+)</Computer>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """Subject:[^=]+?Account Name:\s{0,100}({caller_user}[^:]+?)\s{0,100}Account Domain:\s{0,100}(?=\w)({caller_domain}[^:]+?)\s{0,100}Logon ID:\s{0,100}({logon_id}[^:]+?)\s{0,100}Account That Was""",
    """Account That Was Locked Out:\s{0,100}Security ID:\s{0,100}({user_sid}[^:]+?)\s{0,100}Account Name:\s{0,100}({user}[^:]+?)\s{0,100}Additional""",
    """Caller Computer Name:\s{0,100}(?:\\+)?({src_host}[\w-\.]+)""",
    """<Data Name='TargetUserName'>({user}[^<]+)<""",
    """<Data Name='TargetSid'>({user_sid}[^<]+)<""",
    """<Data Name='SubjectUserName'>({caller_user}[^<]+)<""",
    """<Data Name='SubjectDomainName'>({caller_domain}[^<]+)<""",
    """<Data Name='SubjectLogonId'>({logon_id}[^<]+)<""",
    """<Data Name='TargetDomainName'>(?:\\+)?({src_host}[^<=\s]+)(<|\s)"""
  ]
  DupFields = [ "host->dest_host","caller_domain->domain" ]
}
```