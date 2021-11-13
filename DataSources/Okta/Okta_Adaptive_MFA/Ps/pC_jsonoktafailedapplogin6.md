#### Parser Content
```Java
{
Name = json-okta-failed-app-login-6
  DataType = "failed-app-login"
  Conditions = [ """"core.user_auth.login_failed"""", """requestClientApplication=Okta""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}(?i)FAILURE|INVALID|(?i)failed|(?i)fail)"""
  ]

json-okta-auth = {
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields=[
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"published"{1,20}\s{0,100}:\s{0,100}"{1,20}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """({app}(?i)Okta)""",
    """requestClientApplication=({app}[^=]{1,2000}?)\s{0,100}\w+=""",
    """"city":"({location_city}[^",]{1,2000})""",
    """"state":"({location_state}[^",]{1,2000})""",
    """"country":"({location_country}[^",]{1,2000})""",
    """"ipAddress"{1,20}\s{0,100}:\s{0,100}"{1,20}({src_ip}[^",]{1,2000})""",
    """"rawUserAgent"{1,20}\s{0,100}:\s{0,100}"{1,20}((?i)unknown|({user_agent}[^",]{1,2000}))""",
    """"action"{1,20}:.+?"{1,20}message"{1,20}:"{1,20}({event_name}[^",]{1,2000})"""
    """"displayMessage"\s{0,100}:\s{0,100}"({event_name}[^",]{1,2000})""",
    """"action"{1,20}:.+?"{1,20}objectType"{1,20}:"{1,20}({activity}[^",]{1,2000})""",
    """"legacyEventType"{1,20}:"{1,20}({activity}[^",]{1,2000})""",
    """"reason":"({failure_reason}[^"]{1,2000})"""
    """"target(s)?"{1,20}:[^\}\]]{1,2000}?"{1,20}displayName"{1,20}\s{0,100}:\s{0,100}"{1,20}((?i)unknown|({object}[^"]{1,2000}[^\s]))"""",
    """request"{1,20}:.+?User.+?"{1,20}displayName"{1,20}:(null|"{1,20}(Okta System|(?i)unknown|(?:({user_firstname}[^,"]{1,2000}),\s{0,100}({user_lastname}[^"]{1,2000})|({user_fullname}[^"]{1,2000})))")""",
    """"actor"{1,20}.+?"{1,20}type"{1,20}:"{1,20}User.+?displayName"{1,20}:(null|"{1,20}(Okta System|Okta Admin|(?i)unknown|(?:({user_lastname}[^,"]{1,2000}),\s{0,100}({user_firstname}[^"]{1,2000})|({user_fullname}[^"]{1,2000}))))""",
    """request"{1,20}:.+?"{1,20}type"{1,20}:"{1,20}User"{1,20},"{1,20}alternateId"{1,20}:(null|"{1,20}(system@okta\.com|(?:({user_email}[^"@]{1,2000}@({domain}[^"]{1,2000}))|(({=domain}[^\\\/]{1,2000})[\/\\]{1,2000})?({user}[^"]{1,2000}))))""",
    """"actor"{1,20}:[^\]]{0,2000}?"{1,20}type"{1,20}:"{1,20}User"{1,20},"{1,20}alternateId"{1,20}\s{0,100}:\s{0,100}"{1,20}(system@okta\.com|(?:({user_email}[^"@]{1,2000}@({domain}[^"]{1,2000}))|({user}[^"]{1,2000})))"""",
    """"login":\s{0,100}"({user_email}[^"\s@]{1,2000}@[^"\s@]{1,2000})"""",
    """"login":\s{0,100}"[^@]{1,2000}@({domain}[^"]{1,2000})""""
    """requestUri":\s{0,100}"({request_uri}[^"]{1,2000}?)\s{0,100}"""",
    """"outcome":[^\]]{0,2000}?"result"\s{0,100}:\s{0,100}"({outcome}[^"]{1,2000})"""",
    """outcome":[^\]]{0,2000}?"result":"?(null|({outcome_result_at}[^\"]{1,2000}))"?,"reason":"?(null|({outcome_reason_at}[^"]{1,2000}))""",
  ]
  DupFields = ["domain->email_domain", "failure_reason->additional_info"
}
```