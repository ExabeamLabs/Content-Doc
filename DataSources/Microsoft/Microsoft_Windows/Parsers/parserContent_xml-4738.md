#### Parser Content
```Java
{
Name = xml-4738
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "account-modification"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>4738<""" ]
  Fields = [
    """<EventID>({event_code}\d+)""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]+)""",
    """<Data Name='SubjectUserSid'>({user_sid}[^<]+)""",
    """<Data Name='SubjectUserName'>({user}[^<]+)""",
    """<Data Name='SubjectDomainName'>({domain}[^<]+)""",
    """<Data Name='TargettUserName'>({target_user}[^<]+)""",
    """<Data Name='TargettDomainName'>({target_domain}[^<]+)""",
    """<Data Name='SubjectLogonId'>({logon_id}[^<]+)""",
  ]
}
```