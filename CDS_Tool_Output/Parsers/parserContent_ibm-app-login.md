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
    """({host}[\w\-.]+)\s+sametime-auth\s+[^"]*"({user}[^\s"]+)","({time}\d+\/\d+\/\d\d\d\d\s+\d+:\d+:\d+\s+(am|AM|pm|PM))","({outcome}[^"]+)","({app}[^"]+)","({src_ip}[A-Fa-f:\d.]+)""",
  ]
}
```