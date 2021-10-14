#### Parser Content
```Java
{
Name = s-symantec-dlp-email-alert
    Vendor = Symantec
  Product = Symantec DLP
    Lms = Splunk
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy/MM/dd H:mm:ss"
    Conditions = [ """対象の種類:SMTP""", """送信者:""", """受信者:""", """報告日:""" ]
    Fields = [
      """報告日:({time}\d\d\d\d/\d\d/\d\d \d{1,100}:\d\d:\d\d)""",
      """({host}[\w.\-]{1,2000})\s{1,100}URL:""",
      """インシデント ID:({alert_id}\d{1,100})""",
      """ポリシールール:({alert_type}[^,]{1,2000})""",
      """ポリシー名:({alert_name}[^,]{1,2000})""",
      """件名:\s{0,100}({subject}[^,]{1,2000}?)\s{0,100},""",
      """遮断:({action}[^,]{1,2000})""",
      """受信者:({recipient}[^,@]{1,2000}?@[^,@]{1,2000})""",
      """重大度:({alert_severity}[^,]{1,2000})""",
      """送信者:({sender}[^,@]{1,2000}?@[^,@]{1,2000})""",
      """添付ファイル名:\s{0,100}(N/A|({attachments}(Unknown|({attachment}[^,@\s]{1,2000}))[^,]{0,2000}?))\s{0,100},""",
      """一致件数:\s{0,100}({number_of_violations}\d{1,100})""",
    ]
  }
```