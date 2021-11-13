#### Parser Content
```Java
{
Name = cef-okta-logs-authentication
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = ArcSight
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"actor":""", """"securityContext":""", """"target":""", """"client":""",""""eventType":"app.inbound_del_auth.login_success"""" ]
  Fields=[
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"published"{1,20}\s{0,100}:\s{0,100}"{1,20}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """({app}(?i)Okta)""",
    """requestClientApplication=({app}[^=]{1,2000}?)\s{0,100}\w+=""",
    """"city":"((?i)null|({location_city}[^",]{1,2000}))""",
    """"state":"((?i)null|({location_state}[^",]{1,2000}))""",
    """"country":"((?i)null|({location_country}[^",]{1,2000}))""",
    """"ipAddress"{1,20}\s{0,100}:\s{0,100}"{1,20}({src_ip}[^",]{1,2000})""",
    """"rawUserAgent"{1,20}\s{0,100}:\s{0,100}"{1,20}((?i)unknown|({user_agent}[^",]{1,2000}))""",
    """"browser"{1,20}\s{0,100}:\s{0,100}"{1,20}((?i)unknown|({browser}[^",]{1,2000}))""",
    """"os"{1,20}\s{0,100}:\s{0,100}"{1,20}((?i)unknown|({os}[^",]{1,2000}))""",
    """"displayMessage"\s{0,100}:\s{0,100}"((?i)null|({event_name}[^",]{1,2000}))""",
    """"eventType"\s{0,100}:\s{0,100}"({activity}[^"]{1,2000})""",
    """"legacyEventType"{1,20}:"{1,20}((?i)null|({activity}[^",]{1,2000}))""",
    """"outcome":[^\]]{0,2000}?"result"\s{0,100}:\s{0,100}"(FAILURE|DENY)","reason":"({failure_reason}[^"]{1,2000})""",
    """"reason":"({additional_info}[^"]{1,2000})"""
    """"target(s)?"{1,20}:[^\}\]]{1,2000}?"{1,20}displayName"{1,20}\s{0,100}:\s{0,100}"{1,20}((?i)unknown|({object}[^"]{1,2000}[^\s]))"""",
    """request"{1,20}:.+?User.+?"{1,20}displayName"{1,20}:(null|"{1,20}(Okta System|(?i)unknown|(?:({user_firstname}[^,"]{1,2000}),\s{0,100}({user_lastname}[^"]{1,2000})|({user_fullname}[^"]{1,2000})))")""",
    """"actor"{1,20}.+?"{1,20}type"{1,20}:"{1,20}User.+?displayName"{1,20}:(null|"{1,20}(Okta System|Okta Admin|(?i)unknown|(?:({user_lastname}[^,"]{1,2000}),\s{0,100}({user_firstname}[^"]{1,2000})|({user_fullname}[^"]{1,2000}))))""",
    """request"{1,20}:.+?"{1,20}type"{1,20}:"{1,20}User"{1,20

}
```