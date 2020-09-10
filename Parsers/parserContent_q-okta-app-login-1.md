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
```