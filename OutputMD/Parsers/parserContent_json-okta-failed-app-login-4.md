#### Parser Content
```Java
{
Name = json-okta-failed-app-login-4
  DataType = "failed-app-login"
  Conditions = [ """"app.ad.login.bad_password"""", """requestClientApplication=Okta""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}(?i)FAILURE|(?i)INVALID|(?i)failed|(?i)fail)"""
  ]
}
```