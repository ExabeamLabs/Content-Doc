#### Parser Content
```Java
{
Name = syslog-4768-ch
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4768"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ " 4768 ", """已要求 Kerberos 驗證票證 (TGT)。""" ]
  Fields = [
    """({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})""",
    """\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[\-\+]\d\d:\d\d ({host}[\w.\-]+)\s""",
    """(Information|Audit Success|Success Audit|Failure Audit|Audit Failure)\s*({host}[\w.\-]+?)\s""",
    """({event_code}4768)""",
    """\s帳戶名稱:\s*({user}[^@]+?)(?:@([^\s]+))?\s""",
    """\s支援領域名稱:\s*({domain}\S+)""",
    """\s使用者識別碼:\s*(?:NULL SID|({user_sid}.+?))\s*服務資訊:""",
    """\s用戶端位址:\s*(::[\w]+:)?({dest_ip}(?!::1)[a-fA-F:\d.]+)""",
    """\s結果碼:\s*({result_code}[\w\-]+)"""
  ]
}
```