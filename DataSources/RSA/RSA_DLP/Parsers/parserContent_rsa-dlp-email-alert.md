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
    """DLP_EM:\s*({host}[^\s]+)""",
    """Incident\s*:*\s*"({alert_name}[^"]+)""",
    """Severity=({alert_severity}[^\s]+)""",
    """User=(({domain}[^\\]+)\\)?({user}.+?)\s+\w+=""",
    """Policy=({alert_type}.+?)\s+\w+=""",
    """userEmail=({sender}[^\s]+)""",
    """sessionEmailMailto=({recipients}.+?)\s+\w+=""",
    """sessionEmailMailto=({external_address}[^\s\^]+)""",
    """sessionEmailMailto=[^@]+@({external_domain}[^\s\^]+)""",
    """sessionEmailSubject=({subject}.+?)\s+\w+="""
  ]
}
```