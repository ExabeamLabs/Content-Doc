#### Parser Content
```Java
{
Name = ibm-failed-app-login
  Vendor = IBM
  Product = IBM Sametime
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "MMM/dd/yyyy HH:mm:ss a"
  Conditions = [ """ sametime-auth """, ""","FAILURE",""" ]
  Fields = [
    """({host}[\w\-.]+)\s+sametime-auth\s+[^"]*"({user}[^\s"]+)","({time}\d+\/\d+\/\d\d\d\d\s+\d+:\d+:\d+\s+(am|AM|pm|PM))","({outcome}[^"]+)","({app}[^"]+)","({src_ip}[A-Fa-f:\d.]+)""",
  ]
}
```