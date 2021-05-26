#### Parser Content
```Java
{
Name = s-symantec-dlp-alert-1
    Vendor = Symantec
  Product = Symantec DLP
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "yyyy/MM/dd H:mm:ss"
    Conditions = [ """対象の種類:HTTPS""", """ポリシー名:""", """報告日:""" ]
    Fields = [
      """報告日:({time}\d\d\d\d/\d\d/\d\d \d{1,100}:\d\d:\d\d)""",
      """({host}[\w.\-]{1,2000})\s{1,100}URL:""",
      """インシデント ID:({alert_id}\d{1,100})""",
      """ポリシールール:({alert_type}[^,]{1,2000})""",
      """ポリシー名:({alert_name}[^,]{1,2000})""",
      """遮断:({action}[^,]{1,2000})""",
      """受信者:({target}[^,]{1,2000})""",
      """重大度:({alert_severity}[^,]{1,2000})""",
      """送信者:({src_ip}[^,]{1,2000})""",
      """添付ファイル名:(N/A|({additional_info}[^,]{1,2000}?))\s{0,100}(,|$)""",
      """一致件数:\s{0,100}({number_of_violations}\d{1,100})""",
    ]
  }
```