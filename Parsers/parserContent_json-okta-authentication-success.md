#### Parser Content
```Java
{
Name = json-okta-authentication-success
  DataType = "authentication-successful"
  Conditions = [ """"core.user.factor.attempt_success"""", """requestClientApplication=""", """cs6=""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}SUCCESS|Success|success)"""
  ]
}
```