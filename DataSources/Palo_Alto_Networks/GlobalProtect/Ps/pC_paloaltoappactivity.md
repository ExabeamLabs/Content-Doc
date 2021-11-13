#### Parser Content
```Java
{
Name = palo-alto-app-activity
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,globalprotectgateway-agent-msg,""", """,SYSTEM,""" ]
  Fields = [
    """({host}[\w.\-]{1,2000})\s{1,100}\d{1,100

}
```