#### Parser Content
```Java
{
Name = q-okta-app-login-6
  DataType = "app-login"
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = QRadar
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"eventType"""", """"policy.evaluate_sign_on"""", """policyType""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"published"+:"+({time}[^",]+)"+""",
    """"+actor"+:\{[^\{\}]*?"+alternateId"+:"+(system@okta\.com|({user_email}[^@]+@({domain}[^\.]+\.[^",]+))|(unknown|({user}[^",]+)))"+,""",
    """"+actor"+:\{[^\{\}]*?"+displayName"+:"+(Okta System|Okta Admin|unknown|({user_fullname}[^",]+))"+,""",
    """"policyType"+:"+({alert_type}[^",]+)""",
    """"eventType"+:"+({activity}[^",]+)""",
    """"+result"+:"+({outcome}[^",]+)"+,""",
    """"reason"+:"+({additional_info}[^",]+)"+""",
    """"severity"+:"+({alert_severity}[^",]+)"+""",
    """"+userAgent"+:(null|"+({user_agent}[^",]+))"+""",
    """"outcome"+:[^\]]*?"+result"+:"+FAILURE"+,"+reason"+:"+({failure_reason}[^"]+)"+""",
    """({app}(O|o)kta)"""
    """"type"+:"+AppInstance"+[^\}\]]*"displayName"+:"+({app}[^"]+?)\s*""""
  ]
  DupFields = ["activity->event_name", "app->object"]
}
```