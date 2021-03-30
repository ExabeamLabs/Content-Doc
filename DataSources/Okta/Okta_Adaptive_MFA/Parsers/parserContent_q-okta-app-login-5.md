#### Parser Content
```Java
{
Name = q-okta-app-login-5
  DataType = "app-login"
  Conditions = [ """"message"":""IWA authentication result: SUCCESS""", """"published"":""""" ]
  Fields = ${OktaParserTemplates.q-okta-app-login.Fields}[
    """({event_name}IWA authentication)""",
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