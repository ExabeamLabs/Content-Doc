#### Parser Content
```Java
{
Name = pam-account-switch-2
  DataType = "account-switch"
  Conditions = [ """Transaction: xsso""", """PAM-PRX-0016:""", """, Access/Protocol:""" ]
  Fields = ${PamParserTemplates.pam-authentication.Fields}[
    """({event_name}Executed ""sudo su -"" using transparent login)""",
  ]
}
```