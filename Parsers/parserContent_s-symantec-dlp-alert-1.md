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
      """報告日:({time}\d\d\d\d/\d\d/\d\d \d+:\d\d:\d\d)""",
      """({host}[\w.\-]+)\s+URL:""",
      """インシデント ID:({alert_id}\d+)""",
      """ポリシールール:({alert_type}[^,]+)""",
      """ポリシー名:({alert_name}[^,]+)""",
      """遮断:({action}[^,]+)""",
      """受信者:({target}[^,]+)""",
      """重大度:({alert_severity}[^,]+)""",
      """送信者:({src_ip}[^,]+)""",
      """添付ファイル名:(N/A|({additional_info}[^,]+?))\s*(,|$)""",
      """一致件数:\s*({number_of_violations}\d+)""",
    ]
  }
```