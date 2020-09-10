#### Parser Content
```Java
{
Name = json-okta-failed-app-login-4
  DataType = "failed-app-login"
  Conditions = [ """"app.ad.login.bad_password"""", """requestClientApplication=""", """cs6=""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}FAILURE|INVALID|Failed|failed|fail)"""
  ]
}
```