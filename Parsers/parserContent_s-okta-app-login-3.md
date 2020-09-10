#### Parser Content
```Java
{
Name = s-okta-app-login-3
  DataType = "app-login"
  Conditions = [ """"eventType": "policy.evaluate_sign_on"""" ]
  Fields = ${OktaParserTemplates.s-okta-app-login.Fields}[
    """"country":\s*"({location_country}[^"]+)""",
    """"state":\s*"({location_state}[^"]+)""",
    """"city":\s*"({location_city}[^"]+)""",
  ]
}
```