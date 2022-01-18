#### Parser Content
```Java
{
Name = rsa-dlp-email-alert
  Vendor = RSA
  Product = RSA DLP
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """DLP_EM:""", """protocol=smtp""", """RiskFactor=""", """dlp_event_link""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """DLP_EM:\s{0,100}({host}[^\s]{1,2000})""",
    """Incident\s{0,100}:*\s{0,100}"({alert_name}[^"]{1,2000})""",
    """Severity=({alert_severity}[^\s]{1,2000})""",
    """User=(({domain}[^\\]{1,2000})\\)?({user}.+?)\s{1,100}\w+=""",
    """Policy=({alert_type}.+?)\s{1,100}\w+=""",
    """userEmail=({sender}[^\s]{1,2000})""",
    """sessionEmailMailto=({recipients}.+?)\s{1,100}\w+=""",
    """sessionEmailMailto=({external_address}[^\s\^]{1,2000})""",
    """sessionEmailMailto=[^@]{1,2000}@({external_domain}[^\s\^]{1,2000})""",
    """sessionEmailSubject=({subject}.+?)\s{1,100}\w+="""
  ]


}
```