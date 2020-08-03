#### Parser Content
```Java
{
Name = lumension-failed-usb-activity-4
  Vendor = Lumension
  Product = Lumension
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ ""","READ-DENIED",""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)","[^"]*","(({domain}[^"\\\/]+)[\\\/]+)?({user}[^"\\\/]+)?","({user_ou}[^"]+)","({activity}READ-DENIED)","({host}[^"]+)",("[^"]*",){2}"({file_path}[^"]+)",""",
    ""","({process_name}[^"]+)"\s*$""",
  ]
}
```