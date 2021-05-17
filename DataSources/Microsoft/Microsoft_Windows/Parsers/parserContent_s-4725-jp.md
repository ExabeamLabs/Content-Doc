#### Parser Content
```Java
{
Name = s-4725-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-account-disabled"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ "4725", "ユーザー アカウントが無効化されました。" ]
    Fields = [
      """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4725),""",
      """({host}[\w.\-]{1,2000}),ユーザー アカウントが無効化されました。""",
      """セキュリティ ID:\s{0,100}({user_sid}.*?)\s{0,100}アカウント名:\s{0,100}({user}.*?)\s{0,100}アカウント ドメイン:\s{0,100}({domain}.*?)\s{0,100}ログオン ID:\s{0,100}({logon_id}.*?)\s{0,100}ターゲット.+?セキュリティ ID:\s{0,100}({target_user_sid}.*?)\s{0,100}アカウント名:\s{0,100}({target_user}.*?)\s{0,100}アカウント ドメイン:\s{0,100}({target_domain}.*?)\s{0,100}("|$)"""
    ]
    DupFields = [ "host->dest_host" ]
  }
```