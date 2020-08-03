#### Parser Content
```Java
{
Name = xml-5139
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-ds-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """<EventID>5139</EventID>""", """<Event xmlns='"""  ]
  Fields = [
    """<Computer>({host}.+?)</Computer>""",
    """<TimeCreated SystemTime='({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)\d+Z'/>""",
    """<Data Name='SubjectLogonId'>\s*({logon_id}.+?)\s*</Data>""",
    """<Data Name='SubjectUserName'>\s*(SYSTEM|({user}[^\s]+?))\s*</Data>""",
    """<Data Name='SubjectDomainName'>\s*({domain}[^\s]+?)\s*</Data>""",
    """<Data Name='SubjectUserSid'>\s*({user_sid}[^\s]+?)\s*</Data>""",
    """<Data Name='ObjectClass'>\s*({object_class}.+?)\s*</Data>""",
    """<Data Name='NewObjectDN'>\s*({object_dn}.+?)</Data>\s*""",
    """({event_code}5139)"""
    ]
  DupFields = [ "host->dest_host" ]
}
```