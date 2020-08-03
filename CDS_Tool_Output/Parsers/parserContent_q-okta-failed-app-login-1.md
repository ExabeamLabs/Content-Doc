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
```