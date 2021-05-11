#### Parser Content
```Java
{
Name = ibm-app-login
  Vendor = IBM
  Product = IBM Sametime
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "MMM/dd/yyyy HH:mm:ss a"
  Conditions = [ """ sametime-auth """, ""","SUCCESS",""" ]
  Fields = [
    """({host}[\w\-.]+)\s{1,100}sametime-auth\s{1,100}[^"]*"({user}[^\s"]+)","({time}\d{1,100}\/\d{1,100}\/\d\d\d\d\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am|AM|pm|PM))","({outcome}[^"]+)","({app}[^"]+)","({src_ip}[A-Fa-f:\d.]+)""",
  ]
}
```