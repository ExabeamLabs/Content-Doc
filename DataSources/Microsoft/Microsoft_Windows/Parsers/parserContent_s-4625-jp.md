#### Parser Content
```Java
{
Name = s-4625-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-failed-logon"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [  "アカウントがログオンに失敗しました。" ]
    Fields = [ """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4625),""",
      """(?!\d+)({host}[\w\-.]+),([^,]*,)?アカウントがログオンに失敗しました。""",
      """ComputerName=({computer_name}[\w.\-]+)""",
      """EventCode=({event_code}\d+)""",
      """アカウントがログオンに失敗しました。.+?アカウント名:\s+(?=\w)({caller_user}.+?)\s+アカウント ドメイン:""",
      """アカウントがログオンに失敗しました。.+?アカウント ドメイン:\s+(?=\w)({caller_domain}.+?)\s+ログオン ID:""",
      """ログオン タイプ:\s+({logon_type}[\d]+)""",
      """ログオンを失敗したアカウント:\s+セキュリティ ID:\s+({user_sid}[^\s]+)\s+アカウント名:""",
      """ログオンを失敗したアカウント:.+?アカウント名:\s+(?=\w)({user}.+?)\s+アカウント ドメイン:""",
      """ログオンを失敗したアカウント:.+?アカウント ドメイン:\s+(?=\w)({domain}.+?)\s+エラー情報:""",
      """サブ ステータス:\s+({result_code}[^\s]+) """,
      """ソース ネットワーク アドレス:\s+({src_ip}[a-fA-F:\d.]+)""",
      """ログオン プロセス:\s+({auth_process}[^\s]+)\s+認証パッケージ:\s+({auth_package}[^\s]+)"""
    ]
    DupFields = [ "host->dest_host",
      "computer_name->host" ]
  }
```