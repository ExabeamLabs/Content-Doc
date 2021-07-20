#### Parser Content
```Java
{
Name = s-4771-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-account-lockout"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ "4771", "Kerberos 事前認証に失敗しました。" ]
    Fields = [
      """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4771),""",
      """({host}[\w.\-]{1,2000}),Kerberos 事前認証に失敗しました。""",
      """セキュリティ ID:\s{0,100}({user_sid}.*?)\s{0,100}アカウント名:\s{0,100}({user}.*?)\s{0,100}サービス情報""",
      """サービス名:\s{0,100}\w+\/({domain}.*?)\s{0,100}ネットワーク情報:""",
      """クライアント アドレス:\s{0,100}(::\w+:)?({dest_ip}(?!::1)[a-fA-F:\d.]{1,2000})""",
      """エラー コード:\s{0,100}({result_code}[\w]{1,2000})\s{0,100}事前認証の種類:"""
    ]
  }
```