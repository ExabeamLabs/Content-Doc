#### Parser Content
```Java
{
Name = cef-okta-logs-app-alert
  Vendor = Okta
  Product = Okta MFA
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"actor":""", """"securityContext":""", """"target":""", """"client":""" , """security.password_spray.detected"""]
  Fields=[
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"published"\s*:\s*"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """"displayMessage"\s*:\s*"({additional_info}[^"]+)""",
    """"eventType"\s*:\s*"({alert_name}[^"]+)""",
    """"legacyEventType"\s*:\s*"({alert_name}[^"]+)""",
    """cat=({alert_type}[^\s]+)"""
    """"actor":\s*[^\]]*?"displayName"\s*:\s*"(?:({user_lastname}[^,"]+),\s*({user_firstname}[^"]+)|({user_fullname}[^"]+))"""",
    """"actor":[^\]]*?"alternateId"\s*:\s*"(?:({user_email}[^"@]+@({domain}[^"]+))|({user}[^"]+))"""",
    """"client":[^\]]*?"browser"\s*:\s*"(?:UNKNOWN|({browser}[^"]+))""",
    """"client":[^\]]*?"os"\s*:\s*"(Unknown|({os}[^"]+))""",
    """"client":[^\]]*?"rawUserAgent"\s*:\s*"({user_agent}[^"]+)""",
    """"client":[^\]]*?"ipAddress"\s*:\s*"({src_ip}[^"]+)""",
    """"outcome":[^\]]*?"result"\s*:\s*"FAILURE","reason":"({failure_reason}[^"]+)""",
    """"outcome":[^\]]*?"result"\s*:\s*"({outcome}[^"]+)"""",
    """"target":.+?"displayName"\s*:\s*"({object}[^"]+[^\s])"""",
    """"target":.+?"type"\s*:\s*"({object_type}[^"]+)"""",
    """({app}OKTA)""",
    """({app}Okta)""",
    """"city":"({location_city}[^"]+)""",
    """"state":"({location_state}[^"]+)""",
    """"country":"({location_country}[^"]+)""",
  ]
}
```