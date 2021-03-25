#### Parser Content
```Java
{
Name = xml-5136
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-ds-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """<EventID>5136</EventID>""", """<Event xmlns='"""  ]
  Fields = [
    """<Computer>({host}({dest_host}[\w-]+)[^<]*)</Computer>""",
    """<TimeCreated SystemTime='({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)\d*Z'/>""",
    """<Data Name='SubjectLogonId'>\s*({logon_id}[^<]+?)\s*</Data>""",
    """<Data Name='SubjectUserName'>\s*(SYSTEM|({user}[^<]+?))\s*</Data>""",
    """<Data Name='SubjectDomainName'>\s*({domain}[^<]+?)\s*</Data>""",
    """<Data Name='AttributeLDAPDisplayName'>\s*({attribute}[^<]+?)\s*</Data>""",
    """<Data Name='ObjectClass'>\s*({object_class}[^<]+?)\s*</Data>""",
    """<Data Name='ObjectDN'>\s*({object_dn}[^<]+?)\s*</Data>""",
    """({event_code}5136)"""
    ]
}
```