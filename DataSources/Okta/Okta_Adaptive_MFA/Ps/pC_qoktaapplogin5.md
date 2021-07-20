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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"published"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"message"{1,20}:"{1,20}({event_name}.+?)\s{0,100}(\.|\[|")""",
    """"ipAddress"{1,20}:"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"displayName"{1,20}:"{1,20}((?i)Unknown|RSA-OKTA Admin|AD-OKTA Admin|({user_fullname}[^"]{1,2000}))",[^\{\}]{0,2000}?"objectType"{1,20}:"{1,20}User"""",
    """"login"{1,20}:"{1,20}({user_email}[^"@]{1,2000}@({email_domain}[^"@]{1,2000}))[^\{\}]{0,2000}?"objectType"{1,20}:"{1,20}User"""",
    """"id"{1,20}:"{1,20}({user_agent}[^"]{1,2000})",[^\{\}]{0,2000}?"objectType"{1,20}:"{1,20}Client"""",
    """"displayName"{1,20}:"{1,20}(UNKNOWN|({browser}[^"]{1,2000}))",[^\{\}]{0,2000}?"objectType"{1,20}:"{1,20}Client"""",
    """({app}Okta)""",
    """"displayName"{1,20}:"{1,20}({app}[^"]{1,2000})",[^\{\}]{0,2000}?"objectType"{1,20}:"{1,20}AppInstance"""",
    """"categories.*?objectType"{1,20}:"{1,20}({activity}[^"]{1,2000})"""",
  ]

```