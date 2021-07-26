#### Parser Content
```Java
{
Name = s-skysea-file-download
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "file-download"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [""",Webアクセス,""", """,Webダウンロード,"""]
  Fields = [
    """({host}[^,]{1,2000}),(({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}[\w\-.]{1,2000})),[^,]{0,2000}
```