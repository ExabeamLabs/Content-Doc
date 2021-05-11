#### Parser Content
```Java
{
Name = s-okta-app-login-4
  DataType = "app-login"
  Conditions = [ """"eventType": "app.oauth2.signon"""" ]
  Fields = ${OktaParserTemplates.s-okta-app-login.Fields}[
    """"country":\s{0,100}"({location_country}[^"]+)""",
    """"state":\s{0,100}"({location_state}[^"]+)""",
    """"city":\s{0,100}"({location_city}[^"]+)""",
  ]
}
s-okta-app-login = {
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=({host}[^\s]+)"""   
    """"published":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"userAgent":\s{0,100}\{[^\{\}]*?"rawUserAgent":\s{0,100}"((?i)unknown|({user_agent}[^"]+))""",
    """"userAgent":\s{0,100}\{[^\{\}]*?"browser":\s{0,100}"((?i)unknown|({browser}[^"]+))""",
    """"userAgent":\s{0,100}\{[^\{\}]*?"os":\s{0,100}"((?i)unknown|({os}[^"]+))""",
    """"ip":\s{0,100}"({src_ip}[^"]+)"""",
    """"request":\s{0,100}\{[^\}]+?"ip":\s{0,100}"({src_ip}[a-fA-F:\d.]+)"""",
    """"type":\s{0,100}"({app}[^"]+)""",
    """({app}Okta)""",
    """requestClientApplication=({app}.+?)\s{0,100}\w+=""",
    """"target":\s{0,100}\[.*?\{.*?"displayName":\s{0,100}"({app}[^"]+)"[^\{\}]*?"type":\s{0,100}"AppInstance"""",
    """"type":"AppInstance"[^\}\]]*"displayName":"({app}[^"]+?)\s{0,100}"""",
    """"actor":\s{0,100}\{[^\{\}]*?"displayName":\s{0,100}"((?i)okta[^"]*|unknown|({user_fullname}[^",]+))"[^\{\}]*?"type":\s{0,100}"User"""",
    """"actor":\s{0,100}\{[^\{\}]*?"type":\s{0,100}"User"[^\{\}]*?"displayName":\s{0,100}"((?i)okta[^"]*|unknown|({user_fullname}[^",]+))"""",
    """"actor"":\s{0,100}\{[^\{\}]*?""type"":\s{0,100}""User""[^\{\}]*?""displayName"":\s{0,100}""((?i)okta[^"]*|unknown|({user_lastname}[^,]+),\s{0,100}({user_firstname}[^,"\}\]]+))""""
    """"actor":\s{0,100}\{[^\{\}]*?"alternateId":\s{0,100}"(?:({user_email}[^@"]+@({email_domain}[^@"]+))|({user}[^"@]+))"""",
    """"userName":\s{0,100}"({user_email}[^@"]+@({email_domain}[^@"]+))"""",
    """"outcome":\s{0,100}\{[^\{\}]*?"result":\s{0,100}"({outcome}[^"]+)""",
    """"outcome":\s{0,100}\{[^\{\}]*?"reason":\s{0,100}"({additional_info}[^"]+)""",
    """"redirectUri":\s{0,100}"({object}[^"]+)"""",
    """"displayMessage":\s{0,100}"({activity}[^"]+)"""",
    """"city":\s{0,100}"({location_city}[^"]+)""",
    """"state":\s{0,100}"({location_state}[^"]+)""",
    """"country":\s{0,100}"({location_country}[^"]+)"""
  ]

```