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
    Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4625),""",
      """(?!\d{1,100})({host}[\w\-.]+),([^,]*,)?アカウントがログオンに失敗しました。""",
      """ComputerName=({computer_name}[\w.\-]+)""",
      """EventCode=({event_code}\d{1,100})""",
      """アカウントがログオンに失敗しました。.+?アカウント名:\s{1,100}(?=\w)({caller_user}.+?)\s{1,100}アカウント ドメイン:""",
      """アカウントがログオンに失敗しました。.+?アカウント ドメイン:\s{1,100}(?=\w)({caller_domain}.+?)\s{1,100}ログオン ID:""",
      """ログオン タイプ:\s{1,100}({logon_type}[\d]+)""",
      """ログオンを失敗したアカウント:\s{1,100}セキュリティ ID:\s{1,100}({user_sid}[^\s]+)\s{1,100}アカウント名:""",
      """ログオンを失敗したアカウント:.+?アカウント名:\s{1,100}(?=\w)({user}.+?)\s{1,100}アカウント ドメイン:""",
      """ログオンを失敗したアカウント:.+?アカウント ドメイン:\s{1,100}(?=\w)({domain}.+?)\s{1,100}エラー情報:""",
      """サブ ステータス:\s{1,100}({result_code}[^\s]+) """,
      """ソース ネットワーク アドレス:\s{1,100}({src_ip}[a-fA-F:\d.]+)""",
      """ログオン プロセス:\s{1,100}({auth_process}[^\s]+)\s{1,100}認証パッケージ:\s{1,100}({auth_package}[^\s]+)"""
    ]
    DupFields = [ "host->dest_host",
      "computer_name->host" ]
  }
```