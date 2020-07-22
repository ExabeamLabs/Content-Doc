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
    """({host}[\w.\-]+)\s+\d+,([^,]*,){2}SYSTEM,""",
    """,SYSTEM,([^,]*,){2}({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),([^,]*,){2}(|({object}[^,]+)),""",
    """ Login from:\s*({src_ip}[a-fA-F\d.:]+)""",
    """ User name:\s*({user}[^,]+)""",
    """ Message:\s*({activity}[^,]+)""",
    """ method:\s*({additional_info}[^,]+)""",
    """,({app}globalprotect),""",
  ]
}
```