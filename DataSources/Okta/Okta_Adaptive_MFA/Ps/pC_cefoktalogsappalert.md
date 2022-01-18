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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"published"\s{0,100}:\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """"displayMessage"\s{0,100}:\s{0,100}"({additional_info}[^"]{1,2000})""",
    """"eventType"\s{0,100}:\s{0,100}"({alert_name}[^"]{1,2000})""",
    """"legacyEventType"\s{0,100}:\s{0,100}"({alert_name}[^"]{1,2000})""",
    """cat=({alert_type}[^\s]{1,2000})"""
    """"actor":\s{0,100}[^\]]{0,2000}?"displayName"\s{0,100}:\s{0,100}"(?:({user_lastname}[^,"]{1,2000}),\s{0,100}({user_firstname}[^"]{1,2000})|({user_fullname}[^"]{1,2000}))"""",
    """"actor":[^\]]{0,2000}?"alternateId"\s{0,100}:\s{0,100}"(?:({user_email}[^"@]{1,2000}@({domain}[^"]{1,2000}))|({user}[^"]{1,2000}))"""",
    """"client":[^\]]{0,2000}?"browser"\s{0,100}:\s{0,100}"(?:UNKNOWN|({browser}[^"]{1,2000}))""",
    """"client":[^\]]{0,2000}?"os"\s{0,100}:\s{0,100}"(Unknown|({os}[^"]{1,2000}))""",
    """"client":[^\]]{0,2000}?"rawUserAgent"\s{0,100}:\s{0,100}"({user_agent}[^"]{1,2000})""",
    """"client":[^\]]{0,2000}?"ipAddress"\s{0,100}:\s{0,100}"({src_ip}[^"]{1,2000})""",
    """"outcome":[^\]]{0,2000}?"result"\s{0,100}:\s{0,100}"FAILURE","reason":"({failure_reason}[^"]{1,2000})""",
    """"outcome":[^\]]{0,2000}?"result"\s{0,100}:\s{0,100}"({outcome}[^"]{1,2000})"""",
    """outcome":[^\]]{0,2000}?"result":"?(null|({outcome_result_at}[^\"]{1,2000}))"?,"reason":"?(null|({outcome_reason_at}[^"]{1,2000}))""",
    """"target":.+?"displayName"\s{0,100}:\s{0,100}"({object}[^"]{1,2000}[^\s])"""",
    """"target":.+?"type"\s{0,100}:\s{0,100}"({object_type}[^"]{1,2000})"""",
    """({app}OKTA)""",
    """({app}Okta)""",
    """"city":"({location_city}[^"]{1,2000})""",
    """"state":"({location_state}[^"]{1,2000})""",
    """"country":"({location_country}[^"]{1,2000})""",
  ]


}
```