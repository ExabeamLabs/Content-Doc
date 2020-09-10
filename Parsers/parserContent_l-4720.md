#### Parser Content
```Java
{
Name = l-4720
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4720</EventID>", "A user account was created" ]
  Fields = [
    """({event_name}A user account was created)""",
    	     """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
             """<Computer>({host}[^<]+)</Computer>""",
             """<EventID>({event_code}[^<]+)</EventID>""",
             """Subject:.+?Account Name:\s*({user}.+?)\s*Account Domain:\s*({domain}.+?)\s*Logon ID:\s*({logon_id}.+?)\s*New Account:""",
             """New Account:.+?Security ID:\s*({account_id}.+?)\s*Account Name:\s*({account_name}.+?)\s*Account Domain:\s*({account_domain}.+?)\s*Attributes""" ]
}
```