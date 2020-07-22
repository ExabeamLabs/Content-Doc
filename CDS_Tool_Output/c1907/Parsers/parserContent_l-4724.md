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
    """<Computer>({host}[^<]+)</Computer>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """Subject:.*?Security ID:\s*({user_sid}.+?)\s*Account Name:""",
    """Subject:.*?Account Name:\s*({user}.+?)\s*Account Domain:\s*({domain}.+?)\s*Logon ID:\s*({logon_id}[^\s]+?)\s*Target Account""",
    """Target Account:.*?Security ID:\s*({target_user_sid}.+?)\s*Account Name:\s*(?=\w)({target_user}.+?)\s*Account Domain:\s*(?=\w)({target_domain}[^",\s<]+)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```