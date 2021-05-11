#### Parser Content
```Java
{
Name = s-oam-app-login
  Vendor = Oracle
  Product = Oracle Access Manager
  Lms = Splunk
  DataType = "app-login"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss z"
  Conditions = [ """| AUTHN_""", """OAM_LOGIN |""", """|uid=""" ]
  Fields = [
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d \w+)\s{0,100}\|""",
    """([^\|]*\|){1}\s{0,100}({outcome}[^\|]+?)\s{0,100}\|""",
    """([^\|]*\|){2}\s{0,100}({host}[^\|]+?)\s{0,100}\|""",
    """([^\|]*\|){3}\s{0,100}({additional_info}[^\|]+?)\s{0,100}\|""",
    """([^\|]*\|){5}\s{0,100}({auth_method}[^\|]+?)\s{0,100}\|""",
    """([^\|]*\|){6}\s{0,100}({app}[^\|]+?)_LOGIN\s{0,100}\|""",
    """([^\|]*\|){7}\s{0,100}uid=({user}[^\|\s]+)""",
  ]
}
```