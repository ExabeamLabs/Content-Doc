#### Parser Content
```Java
{
Name = q-okta-failed-app-login-2
  DataType = "failed-app-login"
  Conditions = [ """message""", """Active Directory authentication failed""", """published""" ]
  Fields = ${OktaParserTemplates.q-okta-app-login.Fields}[
    """"Active Directory authentication failed:\s*({failure_reason}[^"]+?)""""
  ]
}
q-okta-app-login = {
  Vendor = Okta
  Product = Okta MFA
  Lms = QRadar
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"published"+:"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """"message"+:"+({event_name}.+?)\s*(\.|\[|")""",
    """"ipAddress"+:"+({src_ip}[a-fA-F\d.:]+)""",
    """"displayName"+:"+({user_fullname}[^"]+)",[^\{\}]*?"objectType"+:"+User"""",
    """"login"+:"+({user_email}[^"@]+@({email_domain}[^"@]+))[^\{\}]*?"objectType"+:"+User"""",
    """"id"+:"+({user_agent}[^"]+)",[^\{\}]*?"objectType"+:"+Client"""",
    """"displayName"+:"+(UNKNOWN|({browser}[^"]+))",[^\{\}]*?"objectType"+:"+Client"""",
    """({app}Okta)""",
    """"displayName"+:"+({app}[^"]+)",[^\{\}]*?"objectType"+:"+AppInstance"""",
    """"categories.*?objectType"+:"+({activity}[^"]+)"""",
  ]

```