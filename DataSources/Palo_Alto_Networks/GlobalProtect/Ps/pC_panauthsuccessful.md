#### Parser Content
```Java
{
Name = pan-auth-successful
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,SYSTEM,auth,""", """,auth-success,""" ]
  Fields = [
    """SYSTEM,auth,[^,]{1,2000}
```