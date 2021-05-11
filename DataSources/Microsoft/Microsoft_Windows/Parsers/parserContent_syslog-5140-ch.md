#### Parser Content
```Java
{
Name = syslog-5140-ch
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "share-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
    Conditions = [ " 5140 ", "已存取網路共用物件。" ]
    Fields = [ 
      """({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})""",
      """\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[\-\+]\d\d:\d\d ({host}[\w.\-]+)\s""",
      """\d{2}:\d{2}:\d{2} ({dest_host}[\w.\-]+)\s""",
      """({event_code}5140)""",
      """\s安全性識別碼:\s{0,100}({user_sid}\S+)\s""",
      """\s帳戶名稱:\s{0,100}({user}[^\s]+)""",
      """\s帳戶網域:\s{0,100}({domain}[^\s]+)""",
      """\s登入識別碼:\s{0,100}({logon_id}[^\s]+)""",
      """\s物件類型:\s{0,100}({file_type}[^\s]+)""",
      """\s來源位址:\s{0,100}({src_ip}[a-fA-F:\d.]+)""",
      """\s來源連接埠:\s{0,100}({src_port}\d{1,100})""",
      """\s共用名稱:\s{0,100}(?:\\+\*\\+)?({share_name}.+?)\s{1,100}共用路徑:""",
      """\s共用路徑:\s{0,100}(?:[\\\?]+)?(?:\s{0,100}|({share_path}(({d_parent}.+?)\\)?({d_name}\s{0,100}\S[^\\]+?))\\?\s{1,100})""",
      """({accesses}Read)"""
    ]
  }
```