#### Parser Content
```Java
{
Name = pan-vpn-login-failed
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "failed-vpn-login"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,globalprotectgateway-regist-fail,""", """GlobalProtect gateway user login failed""" ]
  Fields = [
    """({host}[\w.\-]{1,2000})\s{1,100}\d{1,100}
```