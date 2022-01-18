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
    """Computer(Name)?\s{0,100}\\*"?(=|:|>)\s{0,100}"{0,20}(::ffff:)?({host}[\w\.-]{1,2000})(\s|,|"|</Computer>|$)""",
    """\sComputerName =(::ffff:)?({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100})""",
    """(?i)\w+\s{0,100}\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(am|pm|({host}[\w\-.]{1,2000}))\s""",
    """Security ID:\s{0,100}(|({user_sid}.+?))\s{1,100}Account Name:""",
    """Account Name:\s{0,100}(|({user}.+?))\s{1,100}Account Domain:\s{0,100}(|({domain}.+?))\s{1,100}Logon ID:\s{0,100}(|({logon_id}.+?))\s{1,100}Target Account:""",
    """Target\sAccount.+?Security ID:\s{0,100}({target_sid}.+?)\s""",
    """Target\sAccount.+?Account Name:\s{0,100}({target_user}.+?)\s""",
    """Target\sAccount.+?Account Domain:\s{0,100}({target_domain}.+?)\s""",
    """User Account Control:\s{0,100}.+?\-\s({uac_status}[^\s]{1,2000})\s{1,100}User Parameters""",
    """Changed Attributes:\s{0,100}(|({attribute}.+?))\s{1,100}SAM Account Name""",
    """(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(am|pm|({dest_host}[\w\-.]{1,2000})))\s"""
  ]


}
```