#### Parser Content
```Java
{
Name = cef-o365-security-alert
  Vendor = Microsoft
  Product = Office 365
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """|security-threat-detected|""", """cat=security-alert""", """"riskType":"""" ]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)\s+({host}[\w\-.]+)\s+Skyformation""",
    """({alert_type}({alert_name}IdentityProtection))"""
    """({alert_type}({alert_name}graph-identity-protection-risk-detection))"""
    """"source":"(generic|({alert_type}[^"]+))"""",
    """"riskType":"(generic|({alert_name}[^"]+))"""",
    """"requestId":"({alert_id}[^"]+)"""",
    """"riskLevel":"({alert_severity}[^"]+)"""",
    """"riskType":"({threat_category}[^"]+)"""",
    """"ipAddress":"({src_ip}[A-Fa-f:\d.]+)"""",
    """"userDisplayName":"({user_fullname}[^"]+)"""",
    """"userPrincipalName":"({user_email}[^"@\s]+@[^"@\s]+)"""",
    """msg=({additional_info}.+?)\s+(\w+=|$)""",
    """activity":"({activity}[^"]+)""",
    """"+userAgent"+,"+Value"+:"+({user_agent}[^"]+)""",
    """ext_location_city=({location_city}[^\s]+)""",
    """ext_location_state=({location_state}[^\s]+)""",
    """ext_location_countryOrRegion=({location_country}[^\s]+)""",
    """destinationServiceName=({app}.*?)\s*deviceInboundInterface"""
    """"detectedDateTime"+:"+({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)""",
    """"tokenIssuerType"+:"+({token_issuer_type}[^"]+)""", 
    """"+activity"+:"+({action}[^"]+)""",
    """"+additionalInfo"+:"+\[\{\\"+({more_info}[^]]+)\\"*"""
    
  ]
}
```