#### Parser Content
```Java
{
Name = syslog-4769-ch
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4769"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ " 4769 ", """已要求 Kerberos 服務票證""" ]
  Fields = [
    """({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})""",
    """\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[\-\+]\d\d:\d\d ({host}[\w.\-]+)\s""",
    """(Information|Audit Success|Success Audit|Failure Audit|Audit Failure)\s*({host}[\w.\-]+?)\s""",
    """({event_code}4769)""",
    """\s帳戶名稱:\s*({user}[^@\s]+)(@({domain}[^@\s]+?))?\s""",
    """\s帳戶網域:\s*({domain}\S+)""",
    """\s服務名稱:\s*(([^\/\\]+[\/\\])?({dest_host}[^\/\\\s]+))\s*服務識別碼:""",
    """\s服務名稱:\s*({service_name}\S+)\s*服務識別碼:""",
    """\s票證選項:\s*({ticket_options}\S+)\s*票證加密類型""",
    """\s票證加密類型:\s*({ticket_encryption_type}\S+)\s*""",
    """\s用戶端位址:\s*(::[\w]+:)?({src_ip}(?!::1)[a-fA-F:\d.]+)""",
    """\s用戶端連接埠:\s*({src_port}\d+)""",
    """\s錯誤碼:\s*({result_code}[\w\-]+)"""
  ]
}
```