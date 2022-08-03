#### Parser Content
```Java
{
Name = pan-vpn-login-2
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """globalprotect """, """|login|USERID|""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """end=({time}\d{4}\/\d{2}\/\d{2}\s(\d{2}:){2}\d{2})\s""",
    """src=({src_ip}[A-Fa-f0-9.:]{1,2000})""",
    """({event_name}login)""",
    """duser=(({domain}[^\\\s,]{1,2000})\\+)?({user}[^\\\s,]{1,2000})""",
    """dvchost=({src_host}[\w.-]{1,2000}?)\s""",
    """GPStatus=({outcome}\S{1,2000}?)\s"""
  ]


}
```