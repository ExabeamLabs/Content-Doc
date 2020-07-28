#### Parser Content
```Java
{
Name = s-okta-failed-login-3
  DataType = "failed-app-login"
  Conditions = [ """"eventType": "user.account.lock"""" ]
  Fields = ${OktaParserTemplates.s-okta-app-login.Fields}[
    """"country":\s*"({location_country}[^"]+)""",
    """"state":\s*"({location_state}[^"]+)""",
    """"city":\s*"({location_city}[^"]+)""",
  ]
  DupFields = [ "additional_info->failure_reason" ]
}
```