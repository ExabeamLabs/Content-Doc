#### Parser Content
```Java
{
Name = s-skysea-web-activity-2
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "web-activity"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [""",Webアクセス,""", """,,Webアクセス,"""]
  Fields = [
    """({host}[^,]{1,2000}),(({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}[\w\-.]{1,2000})),[^,]{0,2000}
```