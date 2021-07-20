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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """,USERID,login,\S+,({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d),""", 
    """,USERID,login,.+?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(({domain}[^\\\s,]{1,2000})\\+)?({user}[^\\\s,]{1,2000})""",
  ]
}
```