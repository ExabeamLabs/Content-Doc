#### Parser Content
```Java
{
Name = cef-okta-logs-app-alert
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"actor":""", """"securityContext":""", """"target":""", """"client":""" , """security.password_spray.detected"""]
  Fields=[
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"published"\s{0,100}:\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """"displayMessage"\s{0,100}:\s{0,100}"({additional_info}[^"]+)""",
    """"eventType"\s{0,100}:\s{0,100}"({alert_name}[^"]+)""",
    """"legacyEventType"\s{0,100}:\s{0,100}"({alert_name}[^"]+)""",
    """cat=({alert_type}[^\s]+)"""
    """"actor":\s{0,100}[^\]]*?"displayName"\s{0,100}:\s{0,100}"(?:({user_lastname}[^,"]+),\s{0,100}({user_firstname}[^"]+)|({user_fullname}[^"]+))"""",
    """"actor":[^\]]*?"alternateId"\s{0,100}:\s{0,100}"(?:({user_email}[^"@]+@({domain}[^"]+))|({user}[^"]+))"""",
    """"client":[^\]]*?"browser"\s{0,100}:\s{0,100}"(?:UNKNOWN|({browser}[^"]+))""",
    """"client":[^\]]*?"os"\s{0,100}:\s{0,100}"(Unknown|({os}[^"]+))""",
    """"client":[^\]]*?"rawUserAgent"\s{0,100}:\s{0,100}"({user_agent}[^"]+)""",
    """"client":[^\]]*?"ipAddress"\s{0,100}:\s{0,100}"({src_ip}[^"]+)""",
    """"outcome":[^\]]*?"result"\s{0,100}:\s{0,100}"FAILURE","reason":"({failure_reason}[^"]+)""",
    """"outcome":[^\]]*?"result"\s{0,100}:\s{0,100}"({outcome}[^"]+)"""",
    """outcome":[^\]]*?"result":"?(null|({outcome_result_at}[^\"]+))"?,"reason":"?(null|({outcome_reason_at}[^"]+))""",
    """"target":.+?"displayName"\s{0,100}:\s{0,100}"({object}[^"]+[^\s])"""",
    """"target":.+?"type"\s{0,100}:\s{0,100}"({object_type}[^"]+)"""",
    """({app}OKTA)""",
    """({app}Okta)""",
    """"city":"({location_city}[^"]+)""",
    """"state":"({location_state}[^"]+)""",
    """"country":"({location_country}[^"]+)""",
  ]
}
```