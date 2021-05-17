#### Parser Content
```Java
{
Name = q-mcafee-epo-dlp-alert
  Vendor = McAfee
  Product = McAfee DLP
  Lms = QRadar
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """AnalyzerName: """, """ThreatCategory: ""mail.filter""" ]
  Fields = [
    """[=\s^]DetectedUTC:\s"{0,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """[=\s^]ServerID:\s"{0,20}({host}[\w\-.]{1,2000})"""",
    """[=\s^]AnalyzerHostName:\s"{0,20}({dest_host}[\w\-.]{1,2000})"""",
    """[=\s^]TargetHostName:\s"{0,20}(null|({dest_host}[\w\-.]{1,2000}))"""",
    """[=\s^]SourceHostName:\s"{0,20}(null|({src_host}[\w\-.]{1,2000}))"""",
    """[=\s^]TargetIPV4:\s"{0,20}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """[=\s^]SourceIPV4:\s"{0,20}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """[=\s^]SourceUserName:\s"{0,20}({additional_info}[^"]{1,2000})"""",
    """[=\s^]TargetUserName:\s"{0,20}({target}[^"]{1,2000})"""",
    """[=\s^]TargetUserName:\s"{0,20}({target_1}[^"\s;]{1,2000})""",
    """[=\s^]ThreatType:\s"{0,20}({alert_name}[^"]{1,2000})""",
    """[=\s^]ThreatCategory:\s"{0,20}({alert_type}[^"]{1,2000})"""",
    """[=\s^]TargetFileName:\s"{0,20}\S+\|(Unknown filename|({file_name}[^"]{1,2000}))""",
    """[=\s^]ThreatEventID:\s"{0,20}({alert_id}\d{1,100})""",
    """[=\s^]ThreatSeverity:\s"{0,20}({alert_severity}[^"]{1,2000})""",
    """[=\s^]ThreatActionTaken:\s"{0,20}({outcome}[^"]{1,2000})""",
  ]
}
```