#### Parser Content
```Java
{
Name = q-okta-failed-app-login-1
  DataType = "failed-app-login"
  Conditions = [ """"message"":""Sign-in Failed""", """"published"":""""" ]
  Fields = ${OktaParserTemplates.q-okta-app-login.Fields}[
    """Sign-in Failed\s*-\s*({failure_reason}[^"]+?)""""
  ]
}
q-okta-app-login = {
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = QRadar
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"published"+:"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """"message"+:"+({event_name}.+?)\s*(\.|\[|")""",
    """"ipAddress"+:"+({src_ip}[a-fA-F\d.:]+)""",
    """"displayName"+:"+((?i)Unknown|RSA-OKTA Admin|AD-OKTA Admin|({user_fullname}[^"]+))",[^\{\}]*?"objectType"+:"+User"""",
    """"login"+:"+({user_email}[^"@]+@({email_domain}[^"@]+))[^\{\}]*?"objectType"+:"+User"""",
    """"id"+:"+({user_agent}[^"]+)",[^\{\}]*?"objectType"+:"+Client"""",
    """"displayName"+:"+(UNKNOWN|({browser}[^"]+))",[^\{\}]*?"objectType"+:"+Client"""",
    """({app}Okta)""",
    """"displayName"+:"+({app}[^"]+)",[^\{\}]*?"objectType"+:"+AppInstance"""",
    """"categories.*?objectType"+:"+({activity}[^"]+)"""",
  ]

```