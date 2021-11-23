#### Parser Content
```Java
{
Name = cef-okta-app-login
  DataType = "app-login"
  Conditions = [  """"displayMessage":"User single sign on to app"""", """"result":"SUCCESS"""" , """destinationServiceName =Okta"""]
  Fields = ${OktaParserTemplates.s-okta-app-login.Fields}[
    """"displayMessage":"({event_name}[^"]{1,2000})""",
  ]

s-okta-app-login = {
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})"""   
    """"published":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"userAgent":\s{0,100}\{[^\{\}]{0,2000}?"rawUserAgent":\s{0,100}"((?i)unknown|({user_agent}[^"]{1,2000}))""",
    """"ip":\s{0,100}"({src_ip}[^"]{1,2000})"""",
    """"request":\s{0,100}\{[^\}]{1,2000}?"ip":\s{0,100}"({src_ip}[a-fA-F:\d.]{1,2000})"""",
    """"type":\s{0,100}"({app}[^"]{1,2000})""",
    """({app}Okta)""",
    """destinationServiceName({app}.+?)\s{0,100}\w+=""",
    """"target":\s{0,100}\[.*?\{.*?"displayName":\s{0,100}"({app}[^"]{1,2000})"[^\{\}]{0,2000}?"type":\s{0,100}"AppInstance"""",
    """"type":"AppInstance"[^\}\]]{0,2000}"displayName":"({app}[^"]{1,2000}?)\s{0,100}"""",
    """"actor":\s{0,100}\{[^\{\}]{0,2000}?"displayName":\s{0,100}"((?i)okta[^"]{0,2000}|unknown|({user_fullname}[^",]{1,2000}))"[^\{\}]{0,2000}?"type":\s{0,100}"User"""",
    """"actor":\s{0,100}\{[^\{\}]{0,2000}?"type":\s{0,100}"User"[^\{\}]{0,2000}?"displayName":\s{0,100}"((?i)okta[^"]{0,2000}|unknown|({user_fullname}[^",]{1,2000}))"""",
    """"actor"":\s{0,100}\{[^\{\}]{0,2000}?""type"":\s{0,100}""User""[^\{\}]{0,2000}?""displayName"":\s{0,100}""((?i)okta[^"]{0,2000}|unknown|({user_lastname}[^,]{1,2000}),\s{0,100}({user_firstname}[^,"\}\]]{1,2000}))""""
    """"actor":\s{0,100}\{[^\{\}]{0,2000}?"alternateId":\s{0,100}"(?:({user_email}[^@"]{1,2000}@({email_domain}[^@"]{1,2000}))|({user}[^"@]{1,2000}))"""",
    """"userName":\s{0,100}"({user_email}[^@"]{1,2000}@({email_domain}[^@"]{1,2000}))"""",
    """"outcome":\s{0,100}\{[^\{\}]{0,2000}?"result":\s{0,100}"({outcome}[^"]{1,2000})""",
    """"outcome":\s{0,100}\{[^\{\}]{0,2000}?"reason":\s{0,100}"({additional_info}[^"]{1,2000})""",
    """"redirectUri":\s{0,100}"({object}[^"]{1,2000})"""",
    """"displayMessage":\s{0,100}"({activity}[^"]{1,2000})"""",
    """"city":\s{0,100}"({location_city}[^"]{1,2000})""",
    """"state":\s{0,100}"({location_state}[^"]{1,2000})""",
    """"country":\s{0,100}"({location_country}[^"]{1,2000})"""
  ]
    DupFields=["app->object"
}
```