#### Parser Content
```Java
{
Name = palo-alto-networks-setip
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "vpn-set-ip"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,globalprotectgateway-switch-succ,""", """gateway client switch to SSL tunnel mode succeeded""" ]
  Fields = [
    """({host}[\w.\-]{1,2000})\s{1,100}\d{1,100},({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),[^,]{0,2000},SYSTEM,globalprotect,""",
    """Private IP:\s{0,100}({src_translated_ip}[a-fA-F\d.:]{1,2000}[^\."])""",
    """User name:\s{1,100}({user}[^,]{1,2000})"""
  ]
}
```