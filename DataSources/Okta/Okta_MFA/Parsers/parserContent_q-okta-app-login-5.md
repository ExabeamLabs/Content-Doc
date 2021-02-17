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
```