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
      """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4726),""",
      """({host}[\w.\-]{1,2000}),ユーザー アカウントが削除されました。""",
      """セキュリティ ID:\s{0,100}({user_sid}.*?)\s{0,100}アカウント名:\s{0,100}({user}.*?)\s{0,100}アカウント ドメイン:\s{0,100}({domain}.*?)\s{0,100}ログオン ID:\s{0,100}({logon_id}.*?)\s{0,100}ターゲット.+?セキュリティ ID:\s{0,100}({target_user_sid}.*?)\s{0,100}アカウント名:\s{0,100}({target_user}.*?)\s{0,100}アカウント ドメイン:\s{0,100}({target_domain}.*?)\s{0,100}追加情報"""
    ]
    DupFields = [ "host->dest_host", "target_user->account_name" ]
  }
```