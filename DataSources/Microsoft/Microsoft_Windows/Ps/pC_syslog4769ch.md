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
    """\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[\-\+]\d\d:\d\d ({host}[\w.\-]{1,2000})\s""",
    """(Information|Audit Success|Success Audit|Failure Audit|Audit Failure)\s{0,100}({host}[\w.\-]{1,2000}?)\s""",
    """({event_code}4769)""",
    """\s帳戶名稱:\s{0,100}({user}[^@\s]{1,2000})(@({domain}[^@\s]{1,2000}?))?\s""",
    """\s帳戶網域:\s{0,100}({domain}\S+)""",
    """\s服務名稱:\s{0,100}(([^\/\\]{1,2000}[\/\\])?({dest_host}[^\/\\\s]{1,2000}))\s{0,100}服務識別碼:""",
    """\s服務名稱:\s{0,100}({service_name}\S+)\s{0,100}服務識別碼:""",
    """\s票證選項:\s{0,100}({ticket_options}\S+)\s{0,100}票證加密類型""",
    """\s票證加密類型:\s{0,100}({ticket_encryption_type}\S+)\s{0,100}""",
    """\s用戶端位址:\s{0,100}(::[\w]{1,2000}:)?({src_ip}(?!::1)[a-fA-F:\d.]{1,2000})""",
    """\s用戶端連接埠:\s{0,100}({src_port}\d{1,100})""",
    """\s錯誤碼:\s{0,100}({result_code}[\w\-]{1,2000})"""
  ]


}
```