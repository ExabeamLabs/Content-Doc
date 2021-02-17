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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"published"+:"+({time}[^",]+)"+""",
    """({app}(?i)Okta)""",
    """"+actor"+:\{[^\{\}]*?"+alternateId"+:"+(system@okta\.com|({user_email}[^@]+@({domain}[^\.]+\.[^",]+))|({user}[^",]+))"+,""",
    """"+actor"+:\{[^\{\}]*?"+displayName"+:"+(Okta System|Okta Admin|({user_fullname}[^",]+))"+,""",
    """"policyType"+:"+({alert_type}[^",]+)""",
    """"eventType"+:"+({activity}[^",]+)""",
    """"+result"+:"+({outcome}[^",]+)"+,""",
    """"reason"+:"+({additional_info}[^",]+)"+""",
    """"severity"+:"+({alert_severity}[^",]+)"+""",
    """"+userAgent"+:(null|"+({user_agent}[^",]+))"+""",
    """"outcome"+:[^\]]*?"+result"+:"+FAILURE"+,"+reason"+:"+({failure_reason}[^"]+)"+""",
    """"displayMessage"+:"+({alert_name}[^"]+)""",
    """"city"+:"+({location_city}[^",]+)""",
    """"state"+:"+({location_state}[^",]+)""",
    """"country"+:"+({location_country}[^",]+)"""
    """"type"+:"+AppInstance"+[^\}\]]*"displayName"+:"+({app}[^"]+?)\s*"""",
    """"outcome"+:[^\]]*?"+result"+:"+({outcome}[^",]+)"""",
    """"client"+:[^\]]*?"+ipAddress"+:"+({src_ip}[a-fA-F\d.:]+)"""
    """"client"+:[^\]]*?"+browser"+:"+((?i)unknown|({browser}[^",]+))""",
    """"client"+:[^\]]*?"+os":"+((?i)unknown|({os}[^",]+))""",
    """"client"+:[^\]]*?"+rawUserAgent"+:"+((?i)unknown|({user_agent}[^",]+))""",
    """"target"+:\[\{[^\}\]]+"+type"+:"+({object_type}[^",]+)""""
  ]
  DupFields = ["activity->event_name", "app->object"]
}
```