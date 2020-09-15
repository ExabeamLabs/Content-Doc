#### Parser Content
```Java
{
Name = s-4723-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-password-change"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ "4723", "アカウントのパスワードの変更が試行されました。" ]
    Fields = [
      """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4723),""",
      """({host}[\w.\-]+),アカウントのパスワードの変更が試行されました。""",
      """アカウント名:\s*({user}.*?)\s*アカウント ドメイン:\s*({domain}.*?)\s*ログオン ID:\s*({logon_id}.*?)\s*ターゲット.+?セキュリティ ID:\s*({target_user_sid}.*?)\s*アカウント名:\s*({target_user}.*?)\s*アカウント ドメイン:\s*({target_domain}.*?)\s*追加情報"""
    ]
    DupFields = [ "host->dest_host" ]
  }
```