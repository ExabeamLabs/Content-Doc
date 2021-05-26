#### Parser Content
```Java
{
Name = s-o365-dlp-alert
  Vendor = Microsoft
  Product = Windows Defender
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"From":""", """"Workload":""", """"Actions":""", """"DLPRuleMatch"""" ]
  Fields = [
    """"CreationTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"PolicyName":\s{0,100}"(|({alert_type}[^"]{1,2000}))"(,|\})""",
    """"SensitiveInformation":\s{0,100}\[\{[^\}]{0,2000}?"Location":\s{0,100}"(|({additional_info}[^"]{1,2000}))"(,|\})""",
    """"Severity":\s{0,100}"({alert_severity}[^"]{1,2000})"""",
    """"IncidentId":\s{0,100}"({alert_id}[^"]{1,2000})"""",
    """"Actions":\s{0,100}\["({outcome}[^"]{1,2000})"""",
    """"RuleName":\s{0,100}"(|({alert_name}[^",\(]{1,2000}?)\s{0,100})("|\()""",
    """"FileName":\s{0,100}"(|({file_name}[^"]{1,2000}))"(,|\})""",
    """"From":\s{0,100}"({user_email}[^@"]{1,2000}?@[^@]{1,2000}?)"""",
    """"To":\s{0,100}\[({target}[^\]]{1,2000}?)\]"""
  ]
  DupFields = [ "user_email->user" ]
}
```