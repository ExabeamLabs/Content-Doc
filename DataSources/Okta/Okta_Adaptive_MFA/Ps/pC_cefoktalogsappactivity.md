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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"published"\s{0,100}:\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """"displayMessage"\s{0,100}:\s{0,100}"({event_name}(Kerberos[^",]{1,2000}user)|([^"]{1,2000}))""",
    """"eventType"\s{0,100}:\s{0,100}"({activity}[^"]{1,2000})""",
    """"legacyEventType":"({activity}[^"]{1,2000})"""",
    """actor":\s{0,100}\{[^\}]{1,2000}?alternateId":\s{0,100}"({user}[^"]{1,2000})",[^\}]{1,2000}?"type":\s{0,100}"User"""",
    """actor":\s{0,100}\{[^\}]{1,2000}?displayName":\s{0,100}"({user_fullname}[^"]{1,2000})"[^\}]{1,2000}?type":\s{0,100}"User"""",
    """request"{1,20}:.+?User.+?"{1,20}displayName"{1,20}:(null|"{1,20}(Okta System|(?:({user_firstname}[^,"]{1,2000}),\s{0,100}({user_lastname}[^"]{1,2000})|((?i)Unknown|RSA-OKTA Admin|AD-OKTA Admin|({user_fullname}[^"]{1,2000}))))")""",
    """"actor"{1,20}.+?"{1,20}type"{1,20}:"{1,20}User.+?displayName"{1,20}:(null|"{1,20}(Okta System|Okta Admin|(?:({user_lastname}[^,"]{1,2000}),\s{0,100}({user_firstname}[^"]{1,2000})|((?i)Unknown|RSA-OKTA Admin|AD-OKTA Admin|AD Agent|({user_fullname}[^"]{1,2000})))))""",
    """"client":[^\]]{0,2000}?"browser"\s{0,100}:\s{0,100}"((?i)unknown|({browser}[^"]{1,2000}))""",
    """"client":[^\]]{0,2000}?"os"\s{0,100}:\s{0,100}"((?i)unknown|({os}[^"]{1,2000}))""",
    """"client":[^\]]{0,2000}?"rawUserAgent"\s{0,100}:\s{0,100}"((?i)unknown|({user_agent}[^"]{1,2000}))""",
    """logInfo.request.ipChain.ip="({src_ip}[A-Fa-f\d\.:]{1,2000})""",
    """"client":[^\]]{0,2000}?"ipAddress"\s{0,100}:\s{0,100}"({src_ip}[^"]{1,2000})""",
    """"request":\s{0,100}\{[^\}]{1,2000}?"ip":\s{0,100}"({src_ip}[a-fA-F:\d.]{1,2000})"""",
    """"outcome":[^\]]{0,2000}?"result"\s{0,100}:\s{0,100}"(FAILURE|DENY)","reason":"({failure_reason}[^"]{1,2000})""",
    """"outcome":[^\]]{0,2000}?"result"\s{0,100}:\s{0,100}"({outcome}[^"]{1,2000})"""",
    """outcome":[^\]]{0,2000}?"result":"?(null|({outcome_result_at}[^\"]{1,2000}))"?,"reason":"?(null|({outcome_reason_at}[^"]{1,2000}))""",    
    """"target(s)?"{1,20}:[^\}\]]{1,2000}?"{1,20}displayName"{1,20}\s{0,100}:\s{0,100}"{1,20}((?i)unknown|({object}[^"]{1,2000}[^\s]))"""",
    """"target":[^}\]]{1,2000}?"type"\s{0,100}:\s{0,100}"({object_type}[^"]{1,2000})"""",
    """({app}(?i)Okta)""",
    """destinationServiceName =({app}[^=]{1,2000}?)\s{0,100}\w+=""",
    """"type":"AppInstance"[^\}\]]{0,2000}"displayName":"({app}[^"]{1,2000}?)\s{0,100}"""",
    """"city":"({location_city}[^"]{1,2000})""",
    """"state":"({location_state}[^"]{1,2000})""",
    """"country":"({location_country}[^"]{1,2000})""",
    """request"{1,20}:.+?"{1,20}type"{1,20}:"{1,20}User"{1,20

}
```