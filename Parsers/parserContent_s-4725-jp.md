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
      """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4725),""",
      """({host}[\w.\-]+),ユーザー アカウントが無効化されました。""",
      """セキュリティ ID:\s*({user_sid}.*?)\s*アカウント名:\s*({user}.*?)\s*アカウント ドメイン:\s*({domain}.*?)\s*ログオン ID:\s*({logon_id}.*?)\s*ターゲット.+?セキュリティ ID:\s*({target_user_sid}.*?)\s*アカウント名:\s*({target_user}.*?)\s*アカウント ドメイン:\s*({target_domain}.*?)\s*("|$)"""
    ]
    DupFields = [ "host->dest_host" ]
  }
```