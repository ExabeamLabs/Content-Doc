#### Parser Content
```Java
{
Name = s-4724-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-password-reset"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [ "アカウントのパスワードのリセットが試行されました。"]
    Fields = [ """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4724),""",
      """(?!\d+)({host}[\w\-.]+),([^,]*,)?アカウントのパスワードのリセットが試行されました。""",
      """ComputerName=({computer_name}[\w.\-]+)""",
      """EventCode=({event_code}\d+)""",
      """サブジェクト:.+?アカウント名:\s+({user}.+?)\s+アカウント ドメイン:\s+({domain}.+?)\s+ログオン ID:""",
      """ログオン ID:\s+({logon_id}[^\s]+)""",
      """ターゲット アカウント:.+?セキュリティ ID:\s+({user_sid}.+?)\s+アカウント名:\s+(?=\w)({target_user}.+?)\s+アカウント ドメイン:\s+({target_domain}.*?)\s*$"""
    ]
    DupFields = [ "computer_name->dest_host",
      "computer_name->host" ]
  }
```