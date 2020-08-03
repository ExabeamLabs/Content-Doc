#### Parser Content
```Java
{
Name = s-4740-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-account-lockout"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ "4740", "ユーザー アカウントがロックアウトされました。" ]
    Fields = [
      """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4740),""",
      """({host}[\w.\-]+),ユーザー アカウントがロックアウトされました。""",
      """サブジェクト.+?\s*アカウント名:\s*({caller_user}.*?)\s*アカウント ドメイン:\s*({caller_domain}.*?)\s*ログオン ID:\s*({logon_id}.*?)\s*ロックアウトされたアカウント.+?セキュリティ ID:\s*({user_sid}.*?)\s*アカウント名:\s*({user}.*?)\s*追加情報:.+?呼び出し元コンピューター名:\s*({src_host}.*?)\s*("|$)"""
    ]
    DupFields = [ "host->dest_host", "caller_domain->domain" ]
  }
```