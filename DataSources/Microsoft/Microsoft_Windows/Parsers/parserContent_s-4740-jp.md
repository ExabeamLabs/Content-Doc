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
      """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4740),""",
      """({host}[\w.\-]{1,2000}),ユーザー アカウントがロックアウトされました。""",
      """サブジェクト.+?\s{0,100}アカウント名:\s{0,100}({caller_user}.*?)\s{0,100}アカウント ドメイン:\s{0,100}({caller_domain}.*?)\s{0,100}ログオン ID:\s{0,100}({logon_id}.*?)\s{0,100}ロックアウトされたアカウント.+?セキュリティ ID:\s{0,100}({user_sid}.*?)\s{0,100}アカウント名:\s{0,100}({user}.*?)\s{0,100}追加情報:.+?呼び出し元コンピューター名:\s{0,100}({src_host}.*?)\s{0,100}("|$)"""
    ]
    DupFields = [ "host->dest_host", "caller_domain->domain" ]
  }
```