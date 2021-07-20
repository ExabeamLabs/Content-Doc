#### Parser Content
```Java
{
Name = xml-4801
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4801"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSS"
  Conditions = [ "The workstation was unlocked", "<EventID>4801</EventID>" ]
  Fields = [
    """({event_name}The workstation was unlocked)""",
    """<TimeCreated SystemTime(\\)?='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d\d\d\d\d\d\d)Z'\/>""",
    """<Computer>({host}[^<]{1,2000})<""",
    """<EventID>({event_code}4801)""",
    """Data Name(\\)?='TargetUserName'>({user}[^<]{1,2000})""",
    """Data Name(\\)?='TargetDomainName'>({domain}[^<]{1,2000})""",
    """Data Name(\\)?='TargetLogonId'>({logon_id}[^<]{1,2000})""",
    """Data Name(\\)?='TargetUserSid'>({user_sid}[^<]{1,2000})""",

  ]
  DupFields = [ "host->dest_host" ]
}
```