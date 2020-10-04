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

{
  Name = symantec-print-activity
  Vendor = Symantec
  Product = Symantec
  Lms = Direct
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Endpoint Printer/Fax INCIDENT""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]+)\s+DLP_PROD""",
    """\WURL\s+({additional_info}.+?)\s+FILE_NAME""",
    """\WFILE_NAME\s+({object}.+?)\s+MACHINE_NAME""",
    """\WMACHINE_NAME\s+({src_host}[\w\-.]+)""",
    """\WUSER_NAME\s+(({domain}[^\\\s]+)\\+)?({user_fullname}.+?)\s+APP_NAME""",
    """\WAPP_NAME\s+({app}.+?)\s+MACHINE_IP""",
    """\WMACHINE_IP\s+({src_ip}[A-Fa-f:\d.]+)""",
  ]
}
```