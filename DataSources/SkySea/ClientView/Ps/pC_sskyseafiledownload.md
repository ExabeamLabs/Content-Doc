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
    """({host}[^,]{1,2000}),(({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}[\w\-.]{1,2000})),[^,]{0,2000},({user}[^,]{0,2000}),[^,]{0,2000},[^,]{0,2000},[^,]{0,2000},[^,]{0,2000},Webアクセス""",
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """,Webアクセス,[^,]{0,2000},[^,]{0,2000},({download_source}(?:[^:\\\/\s,"]{1,2000}:[\\\/]{1,2000})?({domain}[^\\\/\s:,"]{1,2000})[^,]{0,2000})""",
    """Webアクセス,([^,]{0,2000},){32}(({file_path}[^=]{1,2000}?)\\+)?({file_name}[^\\]{1,2000}?),""",
  ]
}
```