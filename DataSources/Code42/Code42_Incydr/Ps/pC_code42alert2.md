#### Parser Content
```Java
{
Name = code42-alert-2
  Vendor = Code42
  Product = Code42 Incydr
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions= [ """"actor": """", """Code42""", """destinationServiceName =Custom Application""", """Public Shares""" ]
  Fields = [
    """"observedAt":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)"""",
    """"ALERT_DETAILS"[^\}]{1,2000}?"name":\s{0,100}"({alert_name}[^"]{1,2000})",\s{0,100}"description":\s{0,100}"({additional_info}[^"]{1,2000})",\s{0,100}"actor":\s{0,100}"({user_email}[^"]{1,2000})"""",
    """"ALERT_DETAILS"[^\}]{1,2000}?"id":\s{0,100}"({alert_id}[^"]{1,2000})"""",
    """"severity":\s{0,100}"({alert_severity}[^",]{1,2000})""",
    """"OBSERVATION"[^\}]{1,2000}?"type":\s{0,100}"({alert_type}[^"]{1,2000})"""",
    """"OBSERVED_FILE"[^\}]{1,2000}?("path":\s{0,100}"({file_parent}[^"]{1,2000})",\s{0,100})?"name":\s{0,100}"({file_name}[^"]{1,2000})",\s{0,100}"category":\s{0,100}"({file_type}[^"]{1,2000})",\s{0,100}"size":\s{0,100}({file_size}\d{1,2000}?),"""
    """"sendingIpAddresses":\s{0,100}\["({src_ip}[A-Fa-f\d.:]{1,2000})""""
  ]


}
```