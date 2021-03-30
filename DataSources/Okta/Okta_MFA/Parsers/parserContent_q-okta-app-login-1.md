#### Parser Content
```Java
{
Name = q-okta-app-login-1
  DataType = "app-login"
  Conditions = [ """"message"":""Login from Radius Agent succeeded""", """"published"":""""" ]
  Fields = ${OktaParserTemplates.q-okta-app-login.Fields}[
    """Client ID:\s*({src_host}[^"\s]+)""",
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
    """"login"+:"+({user_email}[^"@]+@[^"@]+)[^\{\}]*?"objectType"+:"+User"""",
    """"id"+:"+({user_agent}[^"]+)",[^\{\}]*?"objectType"+:"+Client"""",
    """"displayName"+:"+(UNKNOWN|({browser}[^"]+))",[^\{\}]*?"objectType"+:"+Client"""",
    """({app}Okta)""",
    """"displayName"+:"+({app}[^"]+)",[^\{\}]*?"objectType"+:"+AppInstance"""",
  ]

```