#### Parser Content
```Java
{
Name = pan-auth-failed
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,globalprotect,""", """user authentication failed""" ]
  Fields = [
    """,globalprotect,\d{1,100}
```