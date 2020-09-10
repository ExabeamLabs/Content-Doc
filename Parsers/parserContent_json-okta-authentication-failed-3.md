#### Parser Content
```Java
{
Name = json-okta-authentication-failed-3
  DataType = "authentication-failed"
  Conditions = [ """"app.ad.agent.user_auth.error"""", """requestClientApplication=""", """cs6=""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}FAILURE|INVALID|Failed|failed|fail)"""
  ]
}
```