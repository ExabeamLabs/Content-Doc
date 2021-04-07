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
    """({time}\w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s+""",
    """({event_code}4767)""",
    """(?i)(success|failure|audit)\s+\w+\s+(::ffff:)?({host}[\w\-.]+)""",
    """Computer(Name)?\s*\\*"?(=|:|>)\s*"*(::ffff:)?({host}[\w\.-]+)(\s|,|"|</Computer>|$)""",
    """(?i)\w+\s*\d+\s\d+:\d+:\d+\s+(::ffff:)?(am|pm|({host}[\w\-.]+))""",
    """Subject:.+?Account Name:\s*({user}.+?)\s*Account Domain:\s*({domain}.+?)\s*Logon ID:\s*({logon_id}.+?)\s*Target Account:""",
    """Target Account:\s*Security ID:\s*({user_sid}.+?)\s*Account Name:\s*({target_user}.+?)\s*Account Domain:\s*({target_domain}.+?)\s"""
  ]
}
```