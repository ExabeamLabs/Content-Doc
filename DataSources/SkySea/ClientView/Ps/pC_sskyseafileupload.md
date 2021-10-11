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
    """({host}[^,]{1,2000}),(({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}[\w\-.]{1,2000})),[^,]{0,2000},({user}[^,]{0,2000}),[^,]{0,2000},[^,]{0,2000},[^,]{0,2000},[^,]{0,2000},Webアクセス""",
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """,Webアクセス,[^,]{0,2000},[^,]{0,2000},({accesses}(?:[^:\\\/\s,"]{1,2000}:[\\\/]{1,2000})?({domain}[^\\\/\s:,"]{1,2000})[^,]{0,2000})""",
    """Webアップロード,([^,]{0,2000},){23}(({src_file_dir}[^=]{1,2000}?)\\+)?({file_name}[^\\]{1,2000}?),""",
    """,Webアップロード,([^,]{0,2000},){72}({app}[^,]{1,2000}),""",
  ]
}
```