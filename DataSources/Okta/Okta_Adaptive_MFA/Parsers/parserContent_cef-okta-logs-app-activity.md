#### Parser Content
```Java
{
Name = cef-okta-logs-app-activity
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"actor":""", """"securityContext":""", """"target":""", """"client":""" ]
  Fields=[
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"published"\s*:\s*"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """"displayMessage"\s*:\s*"({event_name}[^"]+)""",
    """"eventType"\s*:\s*"({activity}[^"]+)""",
    """request"+:.+?User.+?"+displayName"+:(null|"+(Okta System|(?:({user_firstname}[^,"]+),\s*({user_lastname}[^"]+)|((?i)Unknown|RSA-OKTA Admin|AD-OKTA Admin|({user_fullname}[^"]+))))")""",
    """"actor"+.+?"+type"+:"+User.+?displayName"+:(null|"+(Okta System|Okta Admin|(?:({user_lastname}[^,"]+),\s*({user_firstname}[^"]+)|((?i)Unknown|RSA-OKTA Admin|AD-OKTA Admin|({user_fullname}[^"]+)))))""",
    """"client":[^\]]*?"browser"\s*:\s*"((?i)unknown|({browser}[^"]+))""",
    """"client":[^\]]*?"os"\s*:\s*"((?i)unknown|({os}[^"]+))""",
    """"client":[^\]]*?"rawUserAgent"\s*:\s*"((?i)unknown|({user_agent}[^"]+))""",
    """logInfo.request.ipChain.ip="({src_ip}[A-Fa-f\d\.:]+)""",
    """"client":[^\]]*?"ipAddress"\s*:\s*"({src_ip}[^"]+)""",
    """"outcome":[^\]]*?"result"\s*:\s*"FAILURE","reason":"({failure_reason}[^"]+)""",
    """"outcome":[^\]]*?"result"\s*:\s*"({outcome}[^"]+)"""",
    """"target(s)?"+:[^\}\]]+?"+displayName"+\s*:\s*"+((?i)unknown|({object}[^"]+[^\s]))"""",
    """"target":.+?"type"\s*:\s*"({object_type}[^"]+)"""",
    """({app}(?i)Okta)""",
    """requestClientApplication=({app}[^=]+?)\s*\w+=""",
    """"type":"AppInstance"[^\}\]]*"displayName":"({app}[^"]+?)\s*"""",
    """"city":"({location_city}[^"]+)""",
    """"state":"({location_state}[^"]+)""",
    """"country":"({location_country}[^"]+)""",
    """request"+:.+?"+type"+:"+User"+,"+alternateId"+:(null|"+(system@okta\.com|(?:({user_email}[^"@]+@({domain}[^"]+))|({user}[^"]+))))""",
    """"actor"+:[^\]]*?"+type"+:"+User"+,"+alternateId"+\s*:\s*"+(system@okta\.com|(?:({user_email}[^"@]+@({domain}[^"]+))|({user}[^"]+)))"""",
    """"privilegeGranted"+\s*:\s*"+({additional_info}[^"]+)""",
    """fname=({group_name}[^=]+)\s+\w+=""",
    """"severity":"({alert_severity}[^"]+)""",
    """"displayMessage":"({alert_name}[^"]+)""",
    """"eventType":"({alert_type}[^"]+)"""
  ]
  DupFields = ["domain->email_domain", "outcome->result", "app->object"]
}
```