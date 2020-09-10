#### Parser Content
```Java
{
Name = xml-4800
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4800"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """<EventID>4800""", """The workstation was locked""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)""",
    """<Computer>({host}[^<]+)""",
    """({event_name}The workstation was locked)""",
    """({event_code}4800)""",
    """Data Name='TargetUserName'>({user}[^<]+)""",
    """Data Name='TargetDomainName'>({domain}[^<]+)""",
    """Data Name='TargetLogonId'>({logon_id}[^<]+)""",
    """Data Name='TargetUserSid'>({user_sid}[^<]+)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```