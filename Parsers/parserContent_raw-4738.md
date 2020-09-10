#### Parser Content
```Java
{
Name = raw-4738
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "account-modification"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = ["""A user account was changed"""]
  Fields = [
    """({event_name}A user account was changed)""",
    """({event_code}4738)""",
    """Computer(Name)?\s*\\*"?(=|:|>)\s*"*({host}[\w\.-]+)(\s|,|"|</Computer>|$)""",
    """\sComputerName=({host}.+?)(\s+\w+=|\s*$)""",
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """Security ID:\s*(|({user_sid}.+?))\s+Account Name:""",
    """Account Name:\s*(|({user}.+?))\s+Account Domain:\s*(|({domain}.+?))\s+Logon ID:\s*(|({logon_id}.+?))\s+Target Account:""",
    """Target\sAccount.+?Security ID:\s*({target_sid}.+?)\s""",
    """Target\sAccount.+?Account Name:\s*({target_user}.+?)\s""",
    """Target\sAccount.+?Account Domain:\s*({target_domain}.+?)\s""",
    """Changed Attributes:\s*(|({attribute}.+?))\s+SAM Account Name"""
  ]
}
```