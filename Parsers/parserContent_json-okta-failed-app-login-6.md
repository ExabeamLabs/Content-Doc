#### Parser Content
```Java
{
Name = json-okta-failed-app-login-6
  DataType = "failed-app-login"
  Conditions = [ """"core.user_auth.login_failed"""", """requestClientApplication=Okta""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}(?i)FAILURE|INVALID|(?i)failed|(?i)fail)"""
  ]
}
```