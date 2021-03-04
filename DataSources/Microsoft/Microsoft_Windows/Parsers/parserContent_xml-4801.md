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
    """<Computer>({host}[^<]+)<""",
    """<EventID>({event_code}4801)""",
    """Data Name(\\)?='TargetUserName'>({user}[^<]+)""",
    """Data Name(\\)?='TargetDomainName'>({domain}[^<]+)""",
    """Data Name(\\)?='TargetLogonId'>({logon_id}[^<]+)""",
    """Data Name(\\)?='TargetUserSid'>({user_sid}[^<]+)""",

  ]
  DupFields = [ "host->dest_host" ]
}
```