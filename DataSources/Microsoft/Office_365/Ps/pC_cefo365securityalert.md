#### Parser Content
```Java
{
Name = cef-o365-security-alert
  Vendor = Microsoft
  Product = Office 365
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """destinationServiceName =Office 365""", """"detectedDateTime":"""", """dproc=graph-identity-protection-risk-detection""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}Z\s{1,100}[\w\-.]{1,2000}\s{1,100}Skyformation"""
    """({alert_type}({alert_name}IdentityProtection))"""
    """({alert_type}({alert_name}graph-identity-protection-risk-detection))"""
    """"source":"(generic|({alert_type}[^"]{1,2000}))"""",
    """"riskType":"(generic|({alert_name}[^"]{1,2000}))"""",
    """"requestId":"({alert_id}[^"]{1,2000})"""",
    """"riskLevel":"({alert_severity}[^"]{1,2000})"""",
    """"riskType":"({threat_category}[^"]{1,2000})"""",
    """"ipAddress":"({src_ip}[A-Fa-f:\d.]{1,2000})"""",
    """"f3u":"({user_email}[^"@\s]{1,2000}@({email_domain}[^"@\s.]{1,2000}\.[^"@\s]{1,2000}))"""",
    """\ssuser=({user_email}[^@]{1,2000}@[^\s]{1,2000})\s""",
    """"userDisplayName":"({user_fullname}[^"]{1,2000}?)\s{0,100}"""",
    """"userPrincipalName":"({user_email}[^"@\s]{1,2000}@[^"@\s]{1,2000})"""",
    """msg=({additional_info}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """activity":"({activity}[^"]{1,2000})""",
    """"{1,20}userAgent"{1,20

}
```