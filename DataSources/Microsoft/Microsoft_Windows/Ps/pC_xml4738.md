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
    """<EventID>({event_code}\d{1,100})""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({event_name}A user account was changed)""",
    """<Computer>({host}[^<]{1,2000})""",
    """<Data Name='SubjectUserSid'>({user_sid}[^<]{1,2000})""",
    """<Data Name='SubjectUserName'>({user}[^<]{1,2000})""",
    """<Data Name='SubjectDomainName'>({domain}[^<]{1,2000})""",
    """<Data Name='TargetUserName'>({target_user}[^<]{1,2000})""",
    """<Data Name='TargetDomainName'>({target_domain}[^<]{1,2000})""",
    """<Data Name='TargetSid'>({target_user_sid}[^<]{1,2000})""",
    """<Data Name='SubjectLogonId'>({logon_id}[^<]{1,2000})""",
    """<Data Name='OldUacValue'>({old_attribute}[^<]{1,2000})""",
    """<Data Name='NewUacValue'>({new_attribute}[^<]{1,2000})""",
    """Changed Attributes:\s{0,100}(|({attribute}[^:]{1,2000}?))\s{1,100}SAM Account Name:""",
    """User Account Control:\s{0,100}({uac_status}[^:]{1,2000}?)\s{0,100}User Parameters:"""
  ]
}
```