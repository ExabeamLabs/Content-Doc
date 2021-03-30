#### Parser Content
```Java
{
Name = s-okta-app-login-1
    DataType = "app-login"
    Conditions = [ """"displayMessage": "User login to Okta"""", """"legacyEventType": "core.user_auth.login_success"""" ]
    Fields = ${OktaParserTemplates.s-okta-app-login.Fields}[
      """"country":\s*"({location_country}[^"]+)""",
      """"state":\s*"({location_state}[^"]+)""",
      """"city":\s*"({location_city}[^"]+)""",
    ]
  }
s-okta-app-login = {
  Vendor = Okta
  Product = Okta Adaptive Multi-Factor Authentication
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """exabeam_splunk_server=({host}\S+)""",
    """({host}[\w\-.]+) Skyformation """,
    """"published":\s*"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """"userAgent":\s*\{[^\{\}]*?"rawUserAgent":\s*"((?i)unknown|({user_agent}[^"]+))""",
    """"userAgent":\s*\{[^\{\}]*?"browser":\s*"((?i)unknown|({browser}[^"]+))""",
    """"userAgent":\s*\{[^\{\}]*?"os":\s*"((?i)unknown|({os}[^"]+))""",
    """"ip":\s*"({src_ip}[^"]+)"""",
    """"type":\s*"({app}[^"]+)""",
    """({app}Okta)""",
    """"target":\s*\[.*?\{.*?"displayName":\s*"({app}[^"]+)"[^\{\}]*?"type":\s*"AppInstance"""",
    """"actor":\s*\{[^\{\}]*?"displayName":\s*"((?i)okta[^"]*|unknown|({user_fullname}[^",]+))"[^\{\}]*?"type":\s*"User"""",
    """"actor":\s*\{[^\{\}]*?"type":\s*"User"[^\{\}]*?"displayName":\s*"((?i)okta[^"]*|unknown|({user_fullname}[^",]+))"""",
    """"actor"":\s*\{[^\{\}]*?""type"":\s*""User""[^\{\}]*?""displayName"":\s*""((?i)okta[^"]*|unknown|({user_lastname}[^,]+),\s*({user_firstname}[^,"\}\]]+))""""
    """"actor":\s*\{[^\{\}]*?"alternateId":\s*"(?:({user_email}[^@"]+@[^@"]+)|({user}[^"@]+))"""",
    """"userName":\s*"({user_email}[^@"]+@[^@"]+)"""",
    """"outcome":\s*\{[^\{\}]*?"result":\s*"({outcome}[^"]+)""",
    """"outcome":\s*\{[^\{\}]*?"reason":\s*"({additional_info}[^"]+)""",
    """"redirectUri":\s*"({object}[^"]+)"""",
    """"displayMessage":\s*"({activity}[^"]+)"""",
    """"city":\s*"({location_city}[^"]+)""",
    """"state":\s*"({location_state}[^"]+)""",
    """"country":\s*"({location_country}[^"]+)""",
    """"displayName":\s*"({user_fullname}[^"]+)"""
  ]

```