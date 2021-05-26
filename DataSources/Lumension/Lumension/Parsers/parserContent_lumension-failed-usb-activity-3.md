#### Parser Content
```Java
{
Name = lumension-failed-usb-activity-3
  Vendor = Lumension
  Product = Lumension
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ ""","WRITE-DENIED",""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)","[^"]{0,2000}","(({domain}[^"\\\/]{1,2000})[\\\/]{1,2000})?({user}[^"\\\/]{1,2000})?","({user_ou}[^"]{1,2000})","({activity}WRITE-DENIED)","({host}[^"]{1,2000})",("[^"]{0,2000}",){2}"({file_path}[^"]{1,2000})",""",
    ""","({process_name}[^"]{1,2000})"\s{0,100}$""",
  ]
}
```