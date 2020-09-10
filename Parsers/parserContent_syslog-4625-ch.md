#### Parser Content
```Java
{
Name = syslog-4625-ch
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-failed-logon"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
    Conditions = [ " 4625 ", "帳戶無法登入。" ]
    Fields = [ 
      """({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})""",
      """\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[\-\+]\d\d:\d\d ({host}[\w.\-]+)\s""",
      """\d{2}:\d{2}:\d{2} ({dest_host}[\w.\-]+)\s""",
      """({event_code}4625)""",
      """帳戶無法登入。.+?帳戶名稱:\s*(?:-|({caller_user}.+?))\s+帳戶網域:""",
      """帳戶無法登入。.+?帳戶網域:\s*(?:-|({caller_domain}.+?))\s+登入識別碼:""",
      """登入類型:\s+({logon_type}[\d]+)""",
      """登入失敗的帳戶:\s+安全性識別碼:\s+({user_sid}[^\s]+)\s+帳戶名稱:""",
      """登入失敗的帳戶:.+?帳戶名稱:\s+(?=\w)({user}.+?)\s+帳戶網域:""",
      """登入失敗的帳戶:.+?帳戶網域:\s+(?=\w)({domain}.+?)\s+失敗資訊:""",
      """失敗原因:\s*({failure_reason}.+?)\s+狀態:""",
      """子狀態:\s+({result_code}[^\s]+)\s""",
      """來源網路位址:\s+({src_ip}[a-fA-F:\d.]+)""",
      """來源連接埠:\s*({src_port}\d+)""",
      """登入處理程序:\s+({auth_process}[^\s]+)\s+驗證封裝:\s+({auth_package}[^\s]+)"""
    ]
  }
```