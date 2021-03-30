#### Parser Content
```Java
{
Name = s-okta-app-login
  DataType = "app-login"
  Conditions = [ """"displayMessage": "User single sign on to app"""", """"result": "SUCCESS"""" ]
  Fields = ${OktaParserTemplates.s-okta-app-login.Fields}[
    """"country":\s*"({location_country}[^"]+)""",
    """"state":\s*"({location_state}[^"]+)""",
    """"city":\s*"({location_city}[^"]+)""",
  ]
}
```