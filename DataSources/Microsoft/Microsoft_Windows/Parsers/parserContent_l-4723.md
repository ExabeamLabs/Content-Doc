#### Parser Content
```Java
{
Name = l-4723
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-password-change"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4723</EventID>", "An attempt was made to change an account's password" ]
  Fields = [
    """({event_name}An attempt was made to change an account's password)""",
    """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """<EventID>({event_code}[^<]{1,2000})</EventID>""",
    """<Keywords>({outcome}[^<]{1,2000})</Keywords>""",
    """Subject.+?Security ID:\s{0,100}({user_sid}.+?)\s{0,100}Account Name""",
    """Subject.+?Account Name:\s{0,100}({user}.+?)\s{0,100}Account Domain""",
    """Account Domain:\s{0,100}({domain}.+?)\s{0,100}Logon ID:\s{0,100}({logon_id}.+?)\s{0,100}Target Account:""",
    """Target Account.+?Security ID:\s{0,100}({target_user_sid}.+?)\s{0,100}Account Name:""",
    """Target Account.+?Account Name:\s{0,100}({target_user}.+?)\s{0,100}Account Domain:\s{0,100}({target_domain}.+?)\s{0,100}Additional"""
  ]
  DupFields = [ "host->dest_host" ]
}
```