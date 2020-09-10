#### Parser Content
```Java
{
Name = json-okta-authentication-failed-4
  DataType = "authentication-failed"
  Conditions = [ """"iwa.invalid_token"""", """requestClientApplication=""", """cs6=""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}FAILURE|INVALID|Failed|failed|fail)"""
  ]
}
```