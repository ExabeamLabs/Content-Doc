#### Parser Content
```Java
{
Name = s-okta-app-login-4
  DataType = "app-login"
  Conditions = [ """"eventType": "app.oauth2.signon"""" ]
  Fields = ${OktaParserTemplates.s-okta-app-login.Fields}[
    """"country":\s*"({location_country}[^"]+)""",
    """"state":\s*"({location_state}[^"]+)""",
    """"city":\s*"({location_city}[^"]+)""",
  ]
}
```