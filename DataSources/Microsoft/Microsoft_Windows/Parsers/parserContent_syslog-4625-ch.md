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
      """帳戶無法登入。.+?帳戶名稱:\s{0,100}(?:-|({caller_user}.+?))\s{1,100}帳戶網域:""",
      """帳戶無法登入。.+?帳戶網域:\s{0,100}(?:-|({caller_domain}.+?))\s{1,100}登入識別碼:""",
      """登入類型:\s{1,100}({logon_type}[\d]+)""",
      """登入失敗的帳戶:\s{1,100}安全性識別碼:\s{1,100}({user_sid}[^\s]+)\s{1,100}帳戶名稱:""",
      """登入失敗的帳戶:.+?帳戶名稱:\s{1,100}(?=\w)({user}.+?)\s{1,100}帳戶網域:""",
      """登入失敗的帳戶:.+?帳戶網域:\s{1,100}(?=\w)({domain}.+?)\s{1,100}失敗資訊:""",
      """失敗原因:\s{0,100}({failure_reason}.+?)\s{1,100}狀態:""",
      """子狀態:\s{1,100}({result_code}[^\s]+)\s""",
      """來源網路位址:\s{1,100}({src_ip}[a-fA-F:\d.]+)""",
      """來源連接埠:\s{0,100}({src_port}\d{1,100})""",
      """登入處理程序:\s{1,100}({auth_process}[^\s]+)\s{1,100}驗證封裝:\s{1,100}({auth_package}[^\s]+)"""
    ]
  }
```