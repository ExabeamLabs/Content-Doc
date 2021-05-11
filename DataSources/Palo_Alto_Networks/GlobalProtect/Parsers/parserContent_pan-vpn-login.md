#### Parser Content
```Java
{
Name = pan-vpn-login
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,vpn-client,globalprotect,""", """,USERID,login,""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """,USERID,login,\S+,({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d),""", 
    """,USERID,login,.+?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(({domain}[^\\\s,]+)\\+)?({user}[^\\\s,]+)""",
  ]
}
```