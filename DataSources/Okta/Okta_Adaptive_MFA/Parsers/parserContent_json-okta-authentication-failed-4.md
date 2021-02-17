#### Parser Content
```Java
{
Name = json-okta-authentication-failed-4
  DataType = "authentication-failed"
  Conditions = [ """"iwa.invalid_token"""", """requestClientApplication=Okta""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}(?i)FAILURE|(?i)INVALID|(?i)failed|(?i)fail)"""
  ]
}
```