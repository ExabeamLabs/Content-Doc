#### Parser Content
```Java
{
Name = l-4725
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-disabled"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4725</EventID>", "A user account was disabled" ]
  Fields = [
    """({event_name}A user account was disabled)""",
    	      """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
              """<Computer>({host}[^<]+)</Computer>""",
              """<EventID>({event_code}[^<]+)</EventID>""",
              """Subject:.+?Security ID:\s*({user_sid}.+?)\s*Account Name:""",
              """Subject:.+?Account Name:\s*({user}.+?)\s*Account Domain:\s*({domain}.+?)\s*Logon ID""",
              """Logon ID:\s*({logon_id}.+?)\s*Target Account:""",
              """Target Account:\s*Security ID:\s*({target_user_sid}.+?)\s*Account Name:\s*(?=\w)({target_user}.+?)\s*Account Domain""",
              """Target Account.+?Account Domain:\s*(?=\w)({target_domain}.+?)\s*</EventData>"""
  ]
  DupFields = [ "host->dest_host" ]
}
```