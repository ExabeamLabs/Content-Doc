#### Parser Content
```Java
{
Name = s-o365-dlp-alert-1
  Vendor = Microsoft
  Product = Windows Defender
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"From":""", """"Workload":""", """"Actions":""", """"DlpRuleMatch"""" ]
  Fields = [
    """"CreationTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """"PolicyName":\s{0,100}"(|({alert_type}[^"]+))"(,|\})""",
    """"SensitiveInformation":\s{0,100}\[\{[^\}]*?"Location":\s{0,100}"(|({additional_info}[^"]+))"(,|\})""",
    """"Severity":\s{0,100}"({alert_severity}[^"]+)"""",
    """"IncidentId":\s{0,100}"({alert_id}[^"]+)"""",
    """"Actions":\s{0,100}\["({outcome}[^"]+)"""",
    """"RuleName":\s{0,100}"(|({alert_name}[^",\(]+?)\s{0,100})("|\()""",
    """"FileName":\s{0,100}"(|({file_name}[^"]+))"(,|\})""",
    """"From":\s{0,100}"({user_email}[^@"]+?@[^@"]+?)"""",
    """"To":\s{0,100}\[({target}[^\]]+)\]""",
    """src-account-name":"({account_name}[^"]+)"""
  ]
}
```