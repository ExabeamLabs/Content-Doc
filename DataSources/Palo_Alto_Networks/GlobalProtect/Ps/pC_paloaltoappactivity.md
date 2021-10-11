#### Parser Content
```Java
{
Name = palo-alto-app-activity
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,globalprotectgateway-agent-msg,""", """,SYSTEM,""" ]
  Fields = [
    """({host}[\w.\-]{1,2000})\s{1,100}\d{1,100},([^,]{0,2000},){2}SYSTEM,""",
    """,SYSTEM,([^,]{0,2000},){2}({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),([^,]{0,2000},){2}(|({object}[^,]{1,2000})),""",
    """ Login from:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """ User name:\s{0,100}({user}[^,]{1,2000})""",
    """ Message:\s{0,100}({activity}[^,]{1,2000})""",
    """ method:\s{0,100}({additional_info}[^,]{1,2000})""",
    """,({app}globalprotect),""",
  ]
}
```