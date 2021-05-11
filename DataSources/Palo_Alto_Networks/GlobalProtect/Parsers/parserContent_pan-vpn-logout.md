#### Parser Content
```Java
{
Name = pan-vpn-logout
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "vpn-logout"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,vpn-client,globalprotect,""", """,USERID,logout,""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """,USERID,logout,\S+,({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d),""",
    """,USERID,logout,.+?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(({domain}[^\\\s,]+)\\+)?({user}[^\\\s,]+)""",
  ]
}
```