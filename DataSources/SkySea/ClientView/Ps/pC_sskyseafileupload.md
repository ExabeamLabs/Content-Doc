#### Parser Content
```Java
{
Name = s-skysea-file-upload
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "file-upload"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [""",Webアクセス,""", """,Webアップロード,"""]
  Fields = [
    """({host}[^,]{1,2000}),(({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}[\w\-.]{1,2000})),[^,]{0,2000}
```