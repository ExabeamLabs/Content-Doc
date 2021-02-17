#### Parser Content
```Java
{
Name = json-okta-app-login-1
  DataType = "app-login"
  Conditions = [ """"core.user_auth.login_success"""", """requestClientApplication=Okta""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}(?i)success)"""
  ]
}
```