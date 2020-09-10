#### Parser Content
```Java
{
Name = pan-auth-successful-1
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,USERID,login,""" ]
  Fields = [
    """\s(-|({host}[\w\-.]+))\s+\d+,({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+).+?,USERID,login,""",
    """,USERID,login,.+?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(({domain}[^\\\s,]+)\\+)?({user}[^\\\s,]+)""",
    """({app}active-directory)""",
  ]
}
```