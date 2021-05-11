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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"published"\s{0,100}:\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """"displayMessage"\s{0,100}:\s{0,100}"({event_name}[^"]+)""",
    """"eventType"\s{0,100}:\s{0,100}"({activity}[^"]+)""",
    """"legacyEventType":"({activity}[^"]+)"""",
    """request"{1,20}:.+?User.+?"{1,20}displayName"{1,20}:(null|"{1,20}(Okta System|(?:({user_firstname}[^,"]+),\s{0,100}({user_lastname}[^"]+)|((?i)Unknown|RSA-OKTA Admin|AD-OKTA Admin|({user_fullname}[^"]+))))")""",
    """"actor"{1,20}.+?"{1,20}type"{1,20}:"{1,20}User.+?displayName"{1,20}:(null|"{1,20}(Okta System|Okta Admin|(?:({user_lastname}[^,"]+),\s{0,100}({user_firstname}[^"]+)|((?i)Unknown|RSA-OKTA Admin|AD-OKTA Admin|AD Agent|({user_fullname}[^"]+)))))""",
    """"client":[^\]]*?"browser"\s{0,100}:\s{0,100}"((?i)unknown|({browser}[^"]+))""",
    """"client":[^\]]*?"os"\s{0,100}:\s{0,100}"((?i)unknown|({os}[^"]+))""",
    """"client":[^\]]*?"rawUserAgent"\s{0,100}:\s{0,100}"((?i)unknown|({user_agent}[^"]+))""",
    """logInfo.request.ipChain.ip="({src_ip}[A-Fa-f\d\.:]+)""",
    """"client":[^\]]*?"ipAddress"\s{0,100}:\s{0,100}"({src_ip}[^"]+)""",
    """"request":\s{0,100}\{[^\}]+?"ip":\s{0,100}"({src_ip}[a-fA-F:\d.]+)"""",
    """"outcome":[^\]]*?"result"\s{0,100}:\s{0,100}"(FAILURE|DENY)","reason":"({failure_reason}[^"]+)""",
    """"outcome":[^\]]*?"result"\s{0,100}:\s{0,100}"({outcome}[^"]+)"""",
    """outcome":[^\]]*?"result":"?(null|({outcome_result_at}[^\"]+))"?,"reason":"?(null|({outcome_reason_at}[^"]+))""",    
    """"target(s)?"{1,20}:[^\}\]]+?"{1,20}displayName"{1,20}\s{0,100}:\s{0,100}"{1,20}((?i)unknown|({object}[^"]+[^\s]))"""",
    """"target":[^}\]]+?"type"\s{0,100}:\s{0,100}"({object_type}[^"]+)"""",
    """({app}(?i)Okta)""",
    """requestClientApplication=({app}[^=]+?)\s{0,100}\w+=""",
    """"type":"AppInstance"[^\}\]]*"displayName":"({app}[^"]+?)\s{0,100}"""",
    """"city":"({location_city}[^"]+)""",
    """"state":"({location_state}[^"]+)""",
    """"country":"({location_country}[^"]+)""",
    """request"{1,20}:.+?"{1,20}type"{1,20}:"{1,20}User"{1,20}
```