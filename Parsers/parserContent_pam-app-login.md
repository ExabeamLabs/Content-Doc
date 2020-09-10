#### Parser Content
```Java
{
Name = pam-app-login
  DataType = "app-login"
  Conditions = [ """Transaction: sso""", """PAM-PRX-0018:""", """, Access/Protocol:""" ]
  Fields = ${PamParserTemplates.pam-authentication.Fields}[
    """({event_name}Auto-login)""",
  ]
}
```