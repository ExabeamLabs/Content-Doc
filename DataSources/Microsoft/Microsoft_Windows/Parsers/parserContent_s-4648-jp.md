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
    Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """ComputerName=({computer_name}[\w.\-]+)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4648),""",
      """EventCode=({event_code}\w+)""",
      """(?!\d{1,100})({host}[\w\-.]+),([^,]*,)?明示的な資格情報を使用してログオンが試行されました。""",
      """サブジェクト:\s{1,100}セキュリティ ID:\s{1,100}({user_sid}[^\s]+)\s{1,100}アカウント名:\s{1,100}({user}.+?)\s{1,100}アカウント ドメイン:\s{1,100}({domain}[^\s]+)\s{1,100}ログオン ID:\s{1,100}({logon_id}[^\s]+)\s{1,100}""",
      """資格情報が使用されたアカウント:\s{1,100}アカウント名:\s{1,100}({account}[^\s]+)\s{1,100}アカウント ドメイン:\s{1,100}({account_domain}[^\s]+)\s{1,100}"""
      """ターゲット サーバー名:\s{1,100}({dest_host}[^\s]+)""",
      """プロセス ID:\s{1,100}({process_id}\w+)\s{1,100}プロセス名:\s{1,100}({process}({directory}.*?\\)({process_name}[^\\]*?))\s{1,100}ネットワーク情報:""",
      """ネットワーク アドレス:\s{1,100}(?:-|({src_ip}[\d\.]+))"""
    ]
    DupFields = [ "computer_name->host", "directory->process_directory" ]
  }
```