#### Parser Content
```Java
{
Name = xml-5137
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-ds-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>5137</EventID>""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({event_code}5137)""",
    """<Computer>({host}[\w\-\.]+)</Computer>""",
    """<Keywords>({outcome}[^<]+)</Keywords>""",
    """<Data Name='SubjectUserSid'>(|({user_sid}[^<]+?))</Data>""",
    """<Data Name='SubjectUserName'>(|({user}[^<]+?))</Data>""",
    """<Data Name='SubjectDomainName'>(|({domain}[^<]+?))</Data>""",
    """<Data Name='SubjectLogonId'>(|({logon_id}[^<]+?))</Data>""",
    """<Data Name='ObjectDN'>(|({object_dn}[^<]+?))</Data>""",
    """<Data Name='ObjectClass'>(|({object_class}[^<]+?))</Data>""",
    """({event_name}A directory service object was created)""",
  ]
}
```