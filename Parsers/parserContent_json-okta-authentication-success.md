#### Parser Content
```Java
{
Name = json-okta-authentication-success
  DataType = "authentication-successful"
  Conditions = [ """"core.user.factor.attempt_success"""", """requestClientApplication=Okta""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}(?i)success)"""
  ]
}
```