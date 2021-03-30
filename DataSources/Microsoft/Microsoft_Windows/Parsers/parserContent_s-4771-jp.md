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
      """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4771),""",
      """({host}[\w.\-]+),Kerberos 事前認証に失敗しました。""",
      """セキュリティ ID:\s*({user_sid}.*?)\s*アカウント名:\s*({user}.*?)\s*サービス情報""",
      """サービス名:\s*\w+\/({domain}.*?)\s*ネットワーク情報:""",
      """クライアント アドレス:\s*(::\w+:)?({dest_ip}(?!::1)[a-fA-F:\d.]+)""",
      """エラー コード:\s*({result_code}[\w]+)\s*事前認証の種類:"""
    ]
  }
```