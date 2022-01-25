#### Parser Content
```Java
{
Name = s-mcafee-vse-epo-dlp-alert
    Vendor = McAfee
    Product = McAfee DLP
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """AnalyzerName="Data Loss Prevention"""","""ThreatCategory=""" ]
    Fields = [
      """ReceivedUTC="?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """ServerID="({host}[^"]{1,2000}?)"""",
      """SourceHostName="({src_host}[^"]{1,2000}?)"""",
      """TargetHostName="({dest_host}[^"]{1,2000}?)"""",
      """TargetProcessName="({process}[^"]{1,2000}?[\\\/]({process_name}[^"\\\/]{0,2000}))"""",
      """SourceProcessName="({process}[^"]{1,2000}?[\\\/]({process_name}[^"\\\/]{0,2000}))"""",
      """TargetUserName="(({domain}[^"\\\/]{1,2000}?)[\\\/]{1,2000})?({user}[^"]{1,2000})"""",
      """SourceUserName="(({domain}[^"\\\/]{1,2000}?)[\\\/]{1,2000})?({user}[^"]{1,2000})"""",
      """ThreatSeverity="({alert_severity}\d{1,100})""",
      """ThreatName="({alert_name}[^"]{1,2000}?)"""",
      """ThreatType="({alert_type}[^"]{1,2000}?)"""",
      """ThreatEventID="({alert_id}\d{1,100})""",
      """SourceIPV4="({src_ip}[^"]{1,2000})""",
      """TargetIPV4="({dest_ip}[^"]{1,2000})"""
    ]
  }
```