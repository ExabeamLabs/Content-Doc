#### Parser Content
```Java
{
Name = json-okta-failed-app-login-3
  Conditions = [ """EventDetails":""", """User denied access due to sign on policy""", """"DisplayName":"""]
} 
${OktaParserTemplates.q-okta-app-login}{
  Name = q-okta-app-login-1
  DataType = "app-login"
  Conditions = [ """"message"":""Login from Radius Agent succeeded""", """"published"":""""" ]
  Fields = ${OktaParserTemplates.q-okta-app-login.Fields}[
    """Client ID:\s{0,100}({src_host}[^"\s]+)""",
  ]
}
```