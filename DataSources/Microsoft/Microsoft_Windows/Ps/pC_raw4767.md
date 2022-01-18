#### Parser Content
```Java
{
Name = raw-4767
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-unlocked"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """A user account was unlocked""", """Account Name:""" ]
  Fields = [
    """({event_name}A user account was unlocked)""",
    """({time}\w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s{1,100}""",
    """({event_code}4767)""",
    """(?i)(success|failure|audit)\s{1,100}\w+\s{1,100}(::ffff:)?({host}[\w\-.]{1,2000})""",
    """Computer(Name)?\s{0,100}\\*"?(=|:|>)\s{0,100}"{0,20}(::ffff:)?({host}[\w\.-]{1,2000})(\s|,|"|</Computer>|$)""",
    """(?i)\w+\s{0,100}\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(am|pm|({host}[\w\-.]{1,2000}))""",
    """Subject:.+?Account Name:\s{0,100}({user}.+?)\s{0,100}Account Domain:\s{0,100}({domain}.+?)\s{0,100}Logon ID:\s{0,100}({logon_id}.+?)\s{0,100}Target Account:""",
    """Target Account:\s{0,100}Security ID:\s{0,100}({user_sid}.+?)\s{0,100}Account Name:\s{0,100}({target_user}.+?)\s{0,100}Account Domain:\s{0,100}({target_domain}.+?)\s"""
  ]


}
```