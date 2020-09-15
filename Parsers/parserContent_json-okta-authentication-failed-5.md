#### Parser Content
```Java
{
Name = json-okta-authentication-failed-5
  DataType = "authentication-failed"
  Conditions = [ """"core.user.factor.attempt_fail"""", """requestClientApplication=Okta""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}(?i)FAILURE|(?i)INVALID|(?i)failed|(?i)fail)"""
  ]
}
```