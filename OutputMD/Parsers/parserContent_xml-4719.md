#### Parser Content
```Java
{
Name = xml-4719
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-audit"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>4719<""", """<Data Name='SubjectUserName'>""" ]
  Fields = [
    """({event_code}4719)""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]+)""",
    """<Data Name='SubjectUserSid'>({user_sid}[^<]+)""",
    """<Data Name='SubjectUserName'>({user}[^<]+)""",
    """<Data Name='SubjectDomainName'>({domain}[^<]+)""",
    """<Data Name='SubjectLogonId'>({logon_id}[^<]+)""",
    """<Data Name='CategoryId'>({category_id}[^<]+)""",
    """<Data Name='SubcategoryId'>({sub_category_id}[^<]+)""",
    """<Data Name='AuditPolicyChanges'>({policy}[^<]+)""",
  ]
}
```