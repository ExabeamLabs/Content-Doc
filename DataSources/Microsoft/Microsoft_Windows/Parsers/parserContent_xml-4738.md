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
    """({event_name}A user account was changed)""",
    """<Computer>({host}[^<]+)""",
    """<Data Name='SubjectUserSid'>({user_sid}[^<]+)""",
    """<Data Name='SubjectUserName'>({user}[^<]+)""",
    """<Data Name='SubjectDomainName'>({domain}[^<]+)""",
    """<Data Name='TargetUserName'>({target_user}[^<]+)""",
    """<Data Name='TargetDomainName'>({target_domain}[^<]+)""",
    """<Data Name='TargetSid'>({target_user_sid}[^<]+)""",
    """<Data Name='SubjectLogonId'>({logon_id}[^<]+)""",
    """<Data Name='OldUacValue'>({old_attribute}[^<]+)""",
    """<Data Name='NewUacValue'>({new_attribute}[^<]+)""",
    """Changed Attributes:\s*(|({attribute}[^:]+?))\s+SAM Account Name:""",
    """User Account Control:\s*({additional_info}[^:]+?)\s*User Parameters:"""
  ]
}
```