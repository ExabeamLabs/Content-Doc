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
    """<Computer>({host}[^<]+)</Computer>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """<Keywords>({outcome}[^<]+)</Keywords>""",
    """Subject.+?Security ID:\s*({user_sid}.+?)\s*Account Name""",
    """Subject.+?Account Name:\s*({user}.+?)\s*Account Domain""",
    """Account Domain:\s*({domain}.+?)\s*Logon ID:\s*({logon_id}.+?)\s*Target Account:""",
    """Target Account.+?Security ID:\s*({target_user_sid}.+?)\s*Account Name:""",
    """Target Account.+?Account Name:\s*({target_user}.+?)\s*Account Domain:\s*({target_domain}.+?)\s*Additional"""
  ]
  DupFields = [ "host->dest_host" ]
}
```