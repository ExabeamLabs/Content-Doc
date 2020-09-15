#### Parser Content
```Java
{
Name = json-okta-app-login
  DataType = "app-login"
  Conditions = [ """"app.ad.login.success"""", """requestClientApplication=Okta""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}(?i)success)"""
  ]
}
```