#### Parser Content
```Java
{
Name = s-4722-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-account-enabled"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ "4722", "ユーザー アカウントが有効化されました。" ]
    Fields = [
      """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4722),""",
      """({host}[\w.\-]+),ユーザー アカウントが有効化されました。""",
      """アカウント名:\s*({user}.*?)\s*アカウント ドメイン:\s*({domain}.*?)\s*ログオン ID:\s*({logon_id}.*?)\s*ターゲット.+?アカウント名:\s*({target_user}.*?)\s*アカウント ドメイン:\s*({target_domain}.*?)\s*($|")"""
    ]
    DupFields = [ "host->dest_host" ]
  }
```