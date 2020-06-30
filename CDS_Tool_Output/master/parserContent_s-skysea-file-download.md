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
    """({host}[^,]+),(({src_ip}[A-Fa-f:\d.]+)|({src_host}[\w\-.]+)),[^,]*,({user}[^,]*),[^,]*,[^,]*,[^,]*,[^,]*,Webアクセス""",
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """,Webアクセス,[^,]*,[^,]*,({download_source}(?:[^:\\\/\s,"]+:[\\\/]+)?({domain}[^\\\/\s:,"]+)[^,]*)""",
    """Webアクセス,([^,]*,){32}(({file_path}[^=]+?)\\+)?({file_name}[^\\]+?),""",
  ]
}
```