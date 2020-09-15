#### Parser Content
```Java
{
Name = json-okta-failed-app-login-5
  DataType = "failed-app-login"
  Conditions = [ """"app.rich_client.login_failure"""", """requestClientApplication=Okta""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}(?i)FAILURE|(?i)INVALID|(?i)failed|(?i)fail)"""
  ]
}
```