#### Parser Content
```Java
{
Name = s-4624-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-4624"
    TimeFormat = "MM/dd/yyyy HH:mm:ss a"
    Conditions = [ "4624", "アカウントが正常にログオンしました。" ]
    Fields = [ """({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),4624,""",
      """ComputerName=({host}[\w.\-]+)""",
      """(?!\d{1,100})({host}[\w\-.]+),([^,]*,)?アカウントが正常にログオンしました。""",
      """({event_code}4624)""",
      """ログオン タイプ:\s{1,100}({logon_type}[\d]+)""",
      """新しいログオン:.*?アカウント名:\s{1,100}(?:-|({user}[^\\\s]+?))\s{1,100}アカウント ドメイン:\s{1,100}(?:-|({domain}[^\\\s]+?))\s{0,100}ログオン ID:""",
      """プロセス名:\s{1,100}(-|({process}[\w:\\.\-]+))""",
      """ソース ネットワーク アドレス:\s{1,100}(::1|({src_ip}[\w:.]+))""",
      """ログオン プロセス:\s{1,100}({auth_process}[^\s]+)\s{1,100}認証パッケージ:\s{1,100}({auth_package}[^\s]+)""",
      """ログオン ID:\s{1,100}({logon_id}[^\s]+)""",
      """新しいログオン:\s{1,100}セキュリティ ID:\s{1,100}({user_sid}[^\s]+)\s"""
    ]
    DupFields = [ "host->dest_host" ]
  }
```