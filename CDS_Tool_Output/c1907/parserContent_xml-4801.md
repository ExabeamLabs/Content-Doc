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
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d\d\d\d\d\d\d)Z'\/>""",
    """<Computer>({host}[^<]+)<""",
    """({event_code}4801)""",
    """Account Name:\s*({user}.+?)\s*Account Domain""",
    """Account Domain:\s*({domain}.+?)\s*Logon ID""",
    """Logon ID:\s+({logon_id}[^\s]+)\s+Session""",
  ]
  DupFields = [ "host->dest_host" ]
}
```