#### Parser Content
```Java
{
Name = raw-4767
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-account-unlocked"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """A user account was unlocked""", """Account Name:""" ]
  Fields = [
    """({event_name}A user account was unlocked)""",
    """({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(am|AM|pm|PM))""",
    """({time}\w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s{1,100}""",
    """({event_code}4767)""",
    """(?i)(success|failure|audit)\s{1,100}\w+\s{1,100}(::ffff:)?({host}[\w\-.]{1,2000})""",
    """Computer(Name)?\s{0,100}\\{0,25}"?(=|:|>)\s{0,100}"{0,20}(::ffff:)?({host}[\w\.-]{1,2000})(\s|,|"|</Computer>|$)""",
    """(?i)\w+\s{0,100}\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(am|pm|({host}[\w\-.]{1,2000}))""",
    """Subject:.+?Account Name:\s{0,100}({user}[^:]{1,2000}?)\s{0,100}Account Domain:\s{0,100}({domain}[^:]{1,2000}?)\s{0,100}Logon ID:\s{0,100}({logon_id}[^:]{1,2000}?)\s{0,100}Target Account:""",
    """Target Account:\s{0,100}Security ID:\s{0,100}({user_sid}[^:]{1,2000}?)\s{0,100}Account Name:\s{0,100}({target_user}[^:]{1,2000}?)\s{0,100}Account Domain:\s{0,100}({target_domain}[^:]{1,2000}?)("|\s)"""
  ]


}
```