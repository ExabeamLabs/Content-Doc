#### Parser Content
```Java
{
Name = s-oam-app-login
  Vendor = Oracle
  Product = Access Manager
  Lms = Splunk
  DataType = "app-login"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss z"
  Conditions = [ """| AUTHN_""", """OAM_LOGIN |""", """|uid=""" ]
  Fields = [
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d \w+)\s{0,100}\|""",
    """([^\|]{0,2000}\|){1}\s{0,100}({outcome}[^\|]{1,2000}?)\s{0,100}\|""",
    """([^\|]{0,2000}\|){2}\s{0,100}({host}[^\|]{1,2000}?)\s{0,100}\|""",
    """([^\|]{0,2000}\|){3}\s{0,100}({additional_info}[^\|]{1,2000}?)\s{0,100}\|""",
    """([^\|]{0,2000}\|){5}\s{0,100}({auth_method}[^\|]{1,2000}?)\s{0,100}\|""",
    """([^\|]{0,2000}\|){6}\s{0,100}({app}[^\|]{1,2000}?)_LOGIN\s{0,100}\|""",
    """([^\|]{0,2000}\|){7}\s{0,100}uid=({user}[^\|\s]{1,2000})""",
  ]


}
```