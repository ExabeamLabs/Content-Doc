#### Parser Content
```Java
{
Name = json-okta-authentication-failed-3
  DataType = "authentication-failed"
  Conditions = [ """"app.ad.agent.user_auth.error"""", """requestClientApplication=Okta""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}(?i)FAILURE|(?i)INVALID|(?i)failed|(?i)fail)"""
  ]
}
```