#### Parser Content
```Java
{
Name = s-4648-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-account-switch"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [ "明示的な資格情報を使用してログオンが試行されました。" ]
    Fields = [ """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """ComputerName=({computer_name}[\w.\-]+)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4648),""",
      """EventCode=({event_code}\w+)""",
      """(?!\d+)({host}[\w\-.]+),([^,]*,)?明示的な資格情報を使用してログオンが試行されました。""",
      """サブジェクト:\s+セキュリティ ID:\s+({user_sid}[^\s]+)\s+アカウント名:\s+({user}.+?)\s+アカウント ドメイン:\s+({domain}[^\s]+)\s+ログオン ID:\s+({logon_id}[^\s]+)\s+""",
      """資格情報が使用されたアカウント:\s+アカウント名:\s+({account}[^\s]+)\s+アカウント ドメイン:\s+({account_domain}[^\s]+)\s+"""
      """ターゲット サーバー名:\s+({dest_host}[^\s+]+)""",
      """プロセス ID:\s+({process_id}\w+)\s+プロセス名:\s+({process}({directory}.*?\\)({process_name}[^\\]*?))\s+ネットワーク情報:""",
      """ネットワーク アドレス:\s+(?:-|({src_ip}[\d\.]+))"""
    ]
    DupFields = [ "computer_name->host", "directory->process_directory" ]
  }
```