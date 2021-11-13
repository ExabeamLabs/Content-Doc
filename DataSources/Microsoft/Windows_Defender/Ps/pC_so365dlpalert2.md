#### Parser Content
```Java
{
Name = s-o365-dlp-alert-2
  Vendor = Microsoft
  Product = Windows Defender
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """"Operation":"DLPRuleMatch"""", """"RuleName":""", """"PolicyName":""", """"IncidentId":""" ]
  Fields = [
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\d\s{0,100}\d\d:\d\d:\d\d\.\d\d\d)"""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"PolicyName":\s{0,100}"(|({alert_type}[^"]{1,2000}))"(,|\})""",
    """"SensitiveInformation":\s{0,100}\[\{[^\}]{0,2000}?"Location":\s{0,100}"(|({additional_info}[^"]{1,2000}))"(,|\})""",
    """"SensitiveInformationTypeName":"({additional_info}[^"]{1,2000})"""",
    """"Severity":\s{0,100}"({alert_severity}[^"]{1,2000})"""",
    """"IncidentId":\s{0,100}"({alert_id}[^"]{1,2000})"""",
    """"RuleName":\s{0,100}"(|({alert_name}[^",\(]{1,2000}?)\s{0,100})("|\()""",
    """"FileName":\s{0,100}"(|({file_name}[^"]{1,2000}))"(,|\})""",
    """"FileFrom":"({user_email}[^@]{1,2000}@[^"]{1,2000})"""",
    """"FileOwner":"({user_fullname}[^\s\/"]{1,2000}?\s{1,100}[^\/"]{1,2000}?)\/({domain}[^"]{1,2000}?)""""
  ]


}
```