#### Parser Content
```Java
{
Name = s-4724-jp
    Vendor = Microsoft
    Product = Windows
    Lms = Splunk
    DataType = "windows-password-reset"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [ "アカウントのパスワードのリセットが試行されました。"]
    Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4724),""",
      """(?!\d{1,100})({host}[\w\-.]{1,2000}),([^,]{0,2000},)?アカウントのパスワードのリセットが試行されました。""",
      """ComputerName=({computer_name}[\w.\-]{1,2000})""",
      """EventCode=({event_code}\d{1,100})""",
      """サブジェクト:.+?アカウント名:\s{1,100}({user}.+?)\s{1,100}アカウント ドメイン:\s{1,100}({domain}.+?)\s{1,100}ログオン ID:""",
      """ログオン ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
      """ターゲット アカウント:.+?セキュリティ ID:\s{1,100}({user_sid}.+?)\s{1,100}アカウント名:\s{1,100}(?=\w)({target_user}.+?)\s{1,100}アカウント ドメイン:\s{1,100}({target_domain}.*?)\s{0,100}$"""
    ]
    DupFields = [ "computer_name->dest_host",
      "computer_name->host" ]
  }
```