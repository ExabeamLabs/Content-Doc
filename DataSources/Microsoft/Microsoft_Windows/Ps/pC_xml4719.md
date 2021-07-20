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
    """<Computer>({host}[^<]{1,2000})""",
    """<Computer>(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}|({dest_host}[^<]{1,2000}))""",
    """<Data Name='SubjectUserSid'>({user_sid}[^<]{1,2000})""",
    """<Data Name='SubjectUserName'>({user}[^<]{1,2000})""",
    """<Data Name='SubjectDomainName'>({domain}[^<]{1,2000})""",
    """<Data Name='SubjectLogonId'>({logon_id}[^<]{1,2000})""",
    """<Data Name='CategoryId'>({category_id}[^<]{1,2000})""",
    """<Data Name='SubcategoryId'>({sub_category_id}[^<]{1,2000})""",
    """<Data Name='AuditPolicyChanges'>({policy}[^<]{1,2000})""",
  ]
}
```