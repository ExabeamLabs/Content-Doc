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
    """({host}[^,]+),(({src_ip}[A-Fa-f:\d.]+)|({src_host}[\w\-.]+)),[^,]*,({user}[^,]*),[^,]*,[^,]*,[^,]*,[^,]*,Webアクセス""",
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """,Webアクセス,[^,]*,[^,]*,({accesses}(?:[^:\\\/\s,"]+:[\\\/]+)?({domain}[^\\\/\s:,"]+)[^,]*)""",
    """Webアップロード,([^,]*,){23}(({src_file_dir}[^=]+?)\\+)?({file_name}[^\\]+?),""",
    """,Webアップロード,([^,]*,){72}({app}[^,]+),""",
  ]
}
```