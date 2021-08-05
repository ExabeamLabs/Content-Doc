#### Parser Content
```Java
{
Name = xml-5137
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-ds-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>5137</EventID>""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({event_code}5137)""",
    """<Computer>({host}[\w\-\.]{1,2000})</Computer>""",
    """<Keywords>({outcome}[^<]{1,2000})</Keywords>""",
    """<Data Name='SubjectUserSid'>(|({user_sid}[^<]{1,2000}?))</Data>""",
    """<Data Name='SubjectUserName'>(|({user}[^<]{1,2000}?))</Data>""",
    """<Data Name='SubjectDomainName'>(|({domain}[^<]{1,2000}?))</Data>""",
    """<Data Name='SubjectLogonId'>(|({logon_id}[^<]{1,2000}?))</Data>""",
    """<Data Name='ObjectDN'>(|({object_dn}[^<]{1,2000}?))</Data>""",
    """<Data Name='ObjectClass'>(|({object_class}[^<]{1,2000}?))</Data>""",
    """({event_name}A directory service object was created)""",
  ]
}
```