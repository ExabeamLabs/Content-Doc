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
    """DLP_EM:\s{0,100}({host}[^\s]+)""",
    """Incident\s{0,100}:*\s{0,100}"({alert_name}[^"]+)""",
    """Severity=({alert_severity}[^\s]+)""",
    """User=(({domain}[^\\]+)\\)?({user}.+?)\s{1,100}\w+=""",
    """Policy=({alert_type}.+?)\s{1,100}\w+=""",
    """userEmail=({sender}[^\s]+)""",
    """sessionEmailMailto=({recipients}.+?)\s{1,100}\w+=""",
    """sessionEmailMailto=({external_address}[^\s\^]+)""",
    """sessionEmailMailto=[^@]+@({external_domain}[^\s\^]+)""",
    """sessionEmailSubject=({subject}.+?)\s{1,100}\w+="""
  ]
}
```