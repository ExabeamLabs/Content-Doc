#### Parser Content
```Java
{
Name = raw-4738
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "account-modification"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = ["""A user account was changed"""]
  Fields = [
    """({event_name}A user account was changed)""",
    """({event_code}4738)""",
    """Computer(Name)?\s*\\*"?(=|:|>)\s*"*(::ffff:)?({host}[\w\.-]+)(\s|,|"|</Computer>|$)""",
    """\sComputerName=(::ffff:)?({host}.+?)(\s+\w+=|\s*$)""",
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+)""",
    """(?i)\w+\s*\d+\s\d+:\d+:\d+\s+(::ffff:)?(am|pm|({host}[\w\-.]+))\s""",
    """Security ID:\s*(|({user_sid}.+?))\s+Account Name:""",
    """Account Name:\s*(|({user}.+?))\s+Account Domain:\s*(|({domain}.+?))\s+Logon ID:\s*(|({logon_id}.+?))\s+Target Account:""",
    """Target\sAccount.+?Security ID:\s*({target_sid}.+?)\s""",
    """Target\sAccount.+?Account Name:\s*({target_user}.+?)\s""",
    """Target\sAccount.+?Account Domain:\s*({target_domain}.+?)\s""",
    """Changed Attributes:\s*(|({attribute}.+?))\s+SAM Account Name""",
    """(?i)\w+\s*\d+\s*\d+:\d+:\d+\s+(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(am|pm|({dest_host}[\w\-.]+)))\s"""
  ]
}
```