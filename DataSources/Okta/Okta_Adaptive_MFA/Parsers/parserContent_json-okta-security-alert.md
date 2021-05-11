#### Parser Content
```Java
{
Name = json-okta-security-alert
  DataType = "security-alert"
  Conditions = [ """"security.threat.detected"""", """requestClientApplication=Okta""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """"severity"{1,20}:"{1,20}({alert_severity}[^",]+)""",
    """({alert_type}application-action)"""
  ]
  DupFields = [ "event_name->alert_name" ]
}
json-okta-auth = {
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields=[
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"published"{1,20}\s{0,100}:\s{0,100}"{1,20}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """({app}(?i)Okta)""",
    """requestClientApplication=({app}[^=]+?)\s{0,100}\w+=""",
    """"city":"({location_city}[^",]+)""",
    """"state":"({location_state}[^",]+)""",
    """"country":"({location_country}[^",]+)""",
    """"ipAddress"{1,20}\s{0,100}:\s{0,100}"{1,20}({src_ip}[^",]+)""",
    """"rawUserAgent"{1,20}\s{0,100}:\s{0,100}"{1,20}((?i)unknown|({user_agent}[^",]+))""",
    """"browser"{1,20}\s{0,100}:\s{0,100}"{1,20}((?i)unknown|({browser}[^",]+))""",
    """"os"{1,20}\s{0,100}:\s{0,100}"{1,20}((?i)unknown|({os}[^",]+))""",
    """"action"{1,20}:.+?"{1,20}message"{1,20}:"{1,20}({event_name}[^",]+)"""
    """"displayMessage"\s{0,100}:\s{0,100}"({event_name}[^",]+)""",
    """"action"{1,20}:.+?"{1,20}objectType"{1,20}:"{1,20}({activity}[^",]+)""",
    """"legacyEventType"{1,20}:"{1,20}({activity}[^",]+)""",
    """"reason":"({failure_reason}[^"]+)"""
    """"target(s)?"{1,20}:[^\}\]]+?"{1,20}displayName"{1,20}\s{0,100}:\s{0,100}"{1,20}((?i)unknown|({object}[^"]+[^\s]))"""",
    """request"{1,20}:.+?User.+?"{1,20}displayName"{1,20}:(null|"{1,20}(Okta System|(?i)unknown|(?:({user_firstname}[^,"]+),\s{0,100}({user_lastname}[^"]+)|({user_fullname}[^"]+)))")""",
    """"actor"{1,20}.+?"{1,20}type"{1,20}:"{1,20}User.+?displayName"{1,20}:(null|"{1,20}(Okta System|Okta Admin|(?i)unknown|(?:({user_lastname}[^,"]+),\s{0,100}({user_firstname}[^"]+)|({user_fullname}[^"]+))))""",
    """request"{1,20}:.+?"{1,20}type"{1,20}:"{1,20}User"{1,20},"{1,20}alternateId"{1,20}:(null|"{1,20}(system@okta\.com|(?:({user_email}[^"@]+@({domain}[^"]+))|(({=domain}[^\\\/]+)[\/\\]+)?({user}[^"]+))))""",
    """"actor"{1,20}:[^\]]*?"{1,20}type"{1,20}:"{1,20}User"{1,20},"{1,20}alternateId"{1,20}\s{0,100}:\s{0,100}"{1,20}(system@okta\.com|(?:({user_email}[^"@]+@({domain}[^"]+))|({user}[^"]+)))"""",
    """"login":\s{0,100}"({user_email}[^"\s@]+@[^"\s@]+)"""",
    """"login":\s{0,100}"[^@]+@({domain}[^"]+)""""
    """requestUri":\s{0,100}"({request_uri}[^"]+?)\s{0,100}"""",
    """"outcome":[^\]]*?"result"\s{0,100}:\s{0,100}"({outcome}[^"]+)"""",
    """outcome":[^\]]*?"result":"?(null|({outcome_result_at}[^\"]+))"?,"reason":"?(null|({outcome_reason_at}[^"]+))""",
  ]

```