#### Parser Content
```Java
{
Name = json-okta-app-login
  DataType = "app-login"
  Conditions = [ """"app.ad.login.success"""", """requestClientApplication=""", """cs6=""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}SUCCESS|Success|success)"""
  ]
}
```