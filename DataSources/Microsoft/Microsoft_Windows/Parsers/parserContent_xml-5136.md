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
    """<TimeCreated SystemTime='({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)\d{0,100}Z'/>""",
    """<Data Name='SubjectLogonId'>\s{0,100}({logon_id}[^<]+?)\s{0,100}</Data>""",
    """<Data Name='SubjectUserName'>\s{0,100}(SYSTEM|({user}[^<]+?))\s{0,100}</Data>""",
    """<Data Name='SubjectDomainName'>\s{0,100}({domain}[^<]+?)\s{0,100}</Data>""",
    """<Data Name='AttributeLDAPDisplayName'>\s{0,100}({attribute}[^<]+?)\s{0,100}</Data>""",
    """<Data Name='ObjectClass'>\s{0,100}({object_class}[^<]+?)\s{0,100}</Data>""",
    """<Data Name='ObjectDN'>\s{0,100}({object_dn}[^<]+?)\s{0,100}</Data>""",
    """({event_code}5136)"""
    ]
}
```