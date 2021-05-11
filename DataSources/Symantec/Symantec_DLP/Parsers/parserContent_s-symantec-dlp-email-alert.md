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
      """({host}[\w.\-]+)\s{1,100}URL:""",
      """インシデント ID:({alert_id}\d{1,100})""",
      """ポリシールール:({alert_type}[^,]+)""",
      """ポリシー名:({alert_name}[^,]+)""",
      """件名:\s{0,100}({subject}[^,]+?)\s{0,100}
```