#### Parser Content
```Java
{
Name = s-okta-app-login-1
    DataType = "app-login"
    Conditions = [ """"displayMessage": "User login to Okta"""", """"legacyEventType": "core.user_auth.login_success"""" ]
    Fields = ${OktaParserTemplates.s-okta-app-login.Fields}[
      """"country":\s*"({location_country}[^"]+)""",
      """"state":\s*"({location_state}[^"]+)""",
      """"city":\s*"({location_city}[^"]+)""",
    ]
  }
```