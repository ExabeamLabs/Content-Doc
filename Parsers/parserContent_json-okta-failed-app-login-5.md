#### Parser Content
```Java
{
Name = json-okta-failed-app-login-5
  DataType = "failed-app-login"
  Conditions = [ """"app.rich_client.login_failure"""", """requestClientApplication=""", """cs6=""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}FAILURE|INVALID|Failed|failed|fail)"""
  ]
}
```