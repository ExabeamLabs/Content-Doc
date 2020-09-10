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
      """報告日:({time}\d\d\d\d/\d\d/\d\d \d+:\d\d:\d\d)""",
      """({host}[\w.\-]+)\s+URL:""",
      """インシデント ID:({alert_id}\d+)""",
      """ポリシールール:({alert_type}[^,]+)""",
      """ポリシー名:({alert_name}[^,]+)""",
      """件名:\s*({subject}[^,]+?)\s*,""",
      """遮断:({action}[^,]+)""",
      """受信者:({recipient}[^,@]+?@({external_domain_recipient}[^,@]+))""",
      """重大度:({alert_severity}[^,]+)""",
      """送信者:({sender}[^,@]+?@({external_domain_sender}[^,@]+))""",
      """添付ファイル名:\s*(N/A|({attachments}(Unknown|({attachment}[^,@\s]+))[^,]*?))\s*,""",
      """一致件数:\s*({number_of_violations}\d+)""",
    ]
  }
```