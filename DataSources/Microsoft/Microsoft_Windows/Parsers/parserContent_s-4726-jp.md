#### Parser Content
```Java
{
Name = s-4726-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-account-deleted"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ "4726", "ユーザー アカウントが削除されました。" ]
    Fields = [
      """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4726),""",
      """({host}[\w.\-]+),ユーザー アカウントが削除されました。""",
      """セキュリティ ID:\s*({user_sid}.*?)\s*アカウント名:\s*({user}.*?)\s*アカウント ドメイン:\s*({domain}.*?)\s*ログオン ID:\s*({logon_id}.*?)\s*ターゲット.+?セキュリティ ID:\s*({target_user_sid}.*?)\s*アカウント名:\s*({target_user}.*?)\s*アカウント ドメイン:\s*({target_domain}.*?)\s*追加情報"""
    ]
    DupFields = [ "host->dest_host", "target_user->account_name" ]
  }
```