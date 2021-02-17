#### Parser Content
```Java
{
Name = q-okta-failed-app-login-2
  DataType = "failed-app-login"
  Conditions = [ """message""", """Active Directory authentication failed""", """published""" ]
  Fields = ${OktaParserTemplates.q-okta-app-login.Fields}[
    """"Active Directory authentication failed:\s*({failure_reason}[^"]+?)""""
  ]
}
```