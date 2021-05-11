#### Parser Content
```Java
{
Name = cef-o365-security-alert
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """|security-threat-detected|""", """cat=security-alert""", """destinationServiceName=Office 365""","""Security Alert Detected""", """act=detect""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}Z\s{1,100}[\w\-.]+\s{1,100}Skyformation"""
    """({alert_type}({alert_name}IdentityProtection))"""
    """({alert_type}({alert_name}graph-identity-protection-risk-detection))"""
    """"source":"(generic|({alert_type}[^"]+))"""",
    """"riskType":"(generic|({alert_name}[^"]+))"""",
    """"requestId":"({alert_id}[^"]+)"""",
    """"riskLevel":"({alert_severity}[^"]+)"""",
    """"riskType":"({threat_category}[^"]+)"""",
    """"ipAddress":"({src_ip}[A-Fa-f:\d.]+)"""",
    """\ssuser=({user_email}[^@]+@[^\s]+)\s""",
    """"userDisplayName":"({user_fullname}[^"]+?)\s{0,100}"""",
    """"userPrincipalName":"({user_email}[^"@\s]+@[^"@\s]+)"""",
    """msg=({additional_info}[^=]+?)\s{1,100}(\w+=|$)""",
    """activity":"({activity}[^"]+)""",
    """"{1,20}userAgent"{1,20}
```