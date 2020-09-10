#### Parser Content
```Java
{
Name = json-okta-authentication-failed-5
  DataType = "authentication-failed"
  Conditions = [ """"core.user.factor.attempt_fail"""", """requestClientApplication=""", """cs6=""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}FAILURE|INVALID|Failed|failed|fail)"""
  ]
}
```