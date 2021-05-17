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
    """<Computer>({host}[\w\-.]{1,2000})</Computer>""",
    """<EventID>({event_code}\d{1,100})</EventID>""",
    """Subject:.+?Account Name:\s{0,100}({user}.+?)\s{0,100}Account Domain:\s{0,100}({domain}.+?)\s{0,100}Logon ID:\s{0,100}({logon_id}.+?)\s{0,100}Target Account:""",
    """Target Account:\s{0,100}Security ID:\s{0,100}({user_sid}.+?)\s{0,100}Account Name:\s{0,100}({target_user}.+?)\s{0,100}Account Domain:\s{0,100}({target_domain}[^=<]{1,2000})\s{0,100}<"""
  ]
  DupFields = [ "host->dest_host" ]
}
```