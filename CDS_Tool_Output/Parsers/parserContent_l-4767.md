#### Parser Content
```Java
{
Name = l-4767
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-unlocked"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4767</EventID>", "A user account was unlocked" ]
  Fields = [
    """({event_name}A user account was unlocked)""",
    """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[\w\-.]+)</Computer>""",
    """<EventID>({event_code}\d+)</EventID>""",
    """Subject:.+?Account Name:\s*({user}.+?)\s*Account Domain:\s*({domain}.+?)\s*Logon ID:\s*({logon_id}.+?)\s*Target Account:""",
    """Target Account:\s*Security ID:\s*({user_sid}.+?)\s*Account Name:\s*({target_user}.+?)\s*Account Domain:\s*({target_domain}[^=<]+)\s*<"""
  ]
  DupFields = [ "host->dest_host" ]
}
```