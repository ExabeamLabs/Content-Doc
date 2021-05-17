#### Parser Content
```Java
{
Name = syslog-4776-ch
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4776"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ " 4776 ", """電腦嘗試驗證帳戶的認證""" ]
  Fields = [
    """({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})""",
    """\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[\-\+]\d\d:\d\d ({host}[\w.\-]{1,2000})\s""",
    """\d{2}:\d{2}:\d{2} ({dest_host}[\w.\-]{1,2000})\s""",
    """({event_code}4776)""",
    """\s登入帳戶:\s{0,100}({user}[^@\s]{1,2000})(@({domain}[^@\s]{1,2000}?))?\s""",
    """\s來源工作站:\s{0,100}({src_host}\S+?)\s""",
    """\s錯誤碼:\s{0,100}({result_code}[\w\-]{1,2000})"""
  ]
}
```