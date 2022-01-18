#### Parser Content
```Java
{
Name = xml-4767
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-account-unlocked"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """<EventID>4767</EventID>""", """<Event xmlns='"""  ]
  Fields = [
    """<Computer>({host}.+?)</Computer>""",
    """<TimeCreated SystemTime='({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)\d{1,100}Z'/>""",
    """<Data Name ='SubjectLogonId'>\s{0,100}({logon_id}.+?)\s{0,100}</Data>""",
    """<Data Name ='SubjectUserName'>\s{0,100}(SYSTEM|({user}[^\s]{1,2000}?))\s{0,100}</Data>""",
    """<Data Name ='SubjectDomainName'>\s{0,100}({domain}[^\s]{1,2000}?)\s{0,100}</Data>""",
    """<Data Name ='SubjectUserSid'>\s{0,100}({user_sid}[^\s]{1,2000}?)\s{0,100}</Data>""",
    """<Data Name ='TargetDomainName'>\s{0,100}({target_domain}[^\s]{1,2000}?)\s{0,100}</Data>""",
    """<Data Name ='TargetUserName'>\s{0,100}({target_user}[^\s]{1,2000}?)\s{0,100}</Data>""",
    """<Data Name ='TargetSid'>\s{0,100}({target_user_sid}.+?)</Data>\s{0,100}""",
    """({event_code}4767)""",
    ]
  DupFields = [ "host->dest_host" ]


}
```