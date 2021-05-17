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
    """\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[\-\+]\d\d:\d\d ({host}[\w.\-]{1,2000})\s""",
    """(Information|Audit Success|Success Audit|Failure Audit|Audit Failure)\s{0,100}({host}[\w.\-]{1,2000}?)\s""",
    """({event_code}4768)""",
    """\s帳戶名稱:\s{0,100}({user}[^@]{1,2000}?)(?:@([^\s]{1,2000}))?\s""",
    """\s支援領域名稱:\s{0,100}({domain}\S+)""",
    """\s使用者識別碼:\s{0,100}(?:NULL SID|({user_sid}.+?))\s{0,100}服務資訊:""",
    """\s用戶端位址:\s{0,100}(::[\w]{1,2000}:)?({dest_ip}(?!::1)[a-fA-F:\d.]{1,2000})""",
    """\s結果碼:\s{0,100}({result_code}[\w\-]{1,2000})"""
  ]
}
```