#### Parser Content
```Java
{
Name = l-4740
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-lockout"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4740</EventID>", "A user account was locked out" ]
  Fields = [
    """({event_name}A user account was locked out)""",
    """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]+)</Computer>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """Subject:.+?Account Name:\s*({caller_user}.+?)\s*Account Domain:\s*(?=\w)({caller_domain}.+?)\s*Logon ID:\s*({logon_id}.+?)\s*Account That Was""",
    """Account That Was Locked Out:\s*Security ID:\s*({user_sid}.+?)\s*Account Name:\s*({user}.+?)\s*Additional""",
    """Caller Computer Name:\s*(?:\\+)?({src_host}[\w-\.]+)""",
    """<Data Name='TargetUserName'>({user}[^<]+)<""",
    """<Data Name='TargetSid'>({user_sid}[^<]+)<""",
    """<Data Name='SubjectUserName'>({caller_user}[^<]+)<""",
    """<Data Name='SubjectDomainName'>({caller_domain}[^<]+)<""",
    """<Data Name='SubjectLogonId'>({logon_id}[^<]+)<""",
    """<Data Name='TargetDomainName'>(?:\\+)?({src_host}[^<]+)<"""
  ]
  DupFields = [ "host->dest_host",
                "caller_domain->domain" ]
}
```