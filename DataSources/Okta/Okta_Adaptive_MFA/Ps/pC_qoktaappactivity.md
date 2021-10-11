#### Parser Content
```Java
{
Name = q-okta-app-activity
  DataType = "app-activity"
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = QRadar
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"eventType"""", """"client"""", """"target"""", """"securityContext"""", """"actor"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"published"{1,20}:"{1,20}({time}[^",]{1,2000})"{1,20}""",
    """({app}(?i)Okta)""",
    """"{1,20}actor"{1,20}:\{[^\{\}]{0,2000}?"{1,20}alternateId"{1,20}:"{1,20}(system@okta\.com|({user_email}[^@]{1,2000}@({domain}[^\.]{1,2000}\.[^",]{1,2000}))|(unknown|({user}[^",]{1,2000})))"{1,20},""",
    """"{1,20}actor"{1,20}:\{[^\{\}]{0,2000}?"{1,20}displayName"{1,20}:"{1,20}(Okta System|Okta Admin|(unknown|({user_fullname}[^",]{1,2000})))"{1,20},""",
    """"policyType"{1,20}:"{1,20}({alert_type}[^",]{1,2000})""",
    """"eventType"{1,20}:"{1,20}({activity}[^",]{1,2000})""",
    """"{1,20}result"{1,20}:"{1,20}({outcome}[^"]{1,2000})"""",
    """"reason"{1,20}:"{1,20}({additional_info}[^",]{1,2000})"{1,20}""",
    """"severity"{1,20}:"{1,20}({alert_severity}[^",]{1,2000})"{1,20}""",
    """"{1,20}userAgent"{1,20}:(null|"{1,20}({user_agent}[^"]{1,2000}))"{1,20}""",
    """"outcome"{1,20}:[^\]]{0,2000}?"{1,20}result"{1,20}:"{1,20}FAILURE"{1,20},"{1,20}reason"{1,20}:"{1,20}({failure_reason}[^"]{1,2000})"{1,20}""",
    """"displayMessage"{1,20}:"{1,20}({alert_name}[^"]{1,2000})""",
    """"city"{1,20}:"{1,20}({location_city}[^",]{1,2000})""",
    """"state"{1,20}:"{1,20}({location_state}[^",]{1,2000})""",
    """"country"{1,20}:"{1,20}({location_country}[^",]{1,2000})"""
    """"type"{1,20}:"{1,20}AppInstance"{1,20}[^\}\]]{0,2000}"displayName"{1,20}:"{1,20}({app}[^"]{1,2000}?)\s{0,100}"""",
    """"outcome"{1,20}:[^\]]{0,2000}?"{1,20}result"{1,20}:"{1,20}({outcome}[^",]{1,2000})"""",
    """"client"{1,20}:[^\]]{0,2000}?"{1,20}ipAddress"{1,20}:"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})"""
    """"client"{1,20}:[^\]]{0,2000}?"{1,20}browser"{1,20}:"{1,20}((?i)unknown|({browser}[^",]{1,2000}))""",
    """"client"{1,20}:[^\]]{0,2000}?"{1,20}os":"{1,20}((?i)unknown|({os}[^",]{1,2000}))""",
    """"client"{1,20}:[^\]]{0,2000}?"{1,20}rawUserAgent"{1,20}:"{1,20}((?i)unknown|({user_agent}[^"]{1,2000}?))"""",
    """"target"{1,20}:\[\{[^\}\]]{1,2000}"{1,20}type"{1,20}:"{1,20}({object_type}[^",]{1,2000})""""
  ]
  DupFields = ["activity->event_name", "app->object"]
}
```