#### Parser Content
```Java
{
Name = json-okta-failed-app-login-6
  DataType = "failed-app-login"
  Conditions = [ """"core.user_auth.login_failed"""", """requestClientApplication=""", """cs6=""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}FAILURE|INVALID|Failed|failed|fail)"""
  ]
}
```