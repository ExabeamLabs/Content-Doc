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
    """({host}[\w\-.]{1,2000})\s{1,100}sametime-auth\s{1,100}[^"]{0,2000}"({user}[^\s"]{1,2000})","({time}\d{1,100}\/\d{1,100}\/\d\d\d\d\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am|AM|pm|PM))","({outcome}[^"]{1,2000})","({app}[^"]{1,2000})","({src_ip}[A-Fa-f:\d.]{1,2000})""",
  ]
}
```