#### Parser Content
```Java
{
Name = l-4724
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-password-change"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4724</EventID>", "An attempt was made to reset an account's password" ]
  Fields = [
    """({event_name}An attempt was made to reset an account's password)""",
    """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """<EventID>({event_code}[^<]{1,2000})</EventID>""",
    """Subject:.*?Security ID:\s{0,100}({user_sid}.+?)\s{0,100}Account Name:""",
    """Subject:.*?Account Name:\s{0,100}({user}.+?)\s{0,100}Account Domain:\s{0,100}({domain}.+?)\s{0,100}Logon ID:\s{0,100}({logon_id}[^\s]{1,2000}?)\s{0,100}Target Account""",
    """Target Account:.*?Security ID:\s{0,100}({target_user_sid}.+?)\s{0,100}Account Name:\s{0,100}(?=\w)({target_user}.+?)\s{0,100}Account Domain:\s{0,100}(?=\w)({target_domain}[^",\s<]{1,2000})""",
  ]
  DupFields = [ "host->dest_host" ]
}
```