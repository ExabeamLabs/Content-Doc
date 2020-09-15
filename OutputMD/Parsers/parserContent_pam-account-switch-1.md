#### Parser Content
```Java
{
Name = pam-account-switch-1
  DataType = "account-switch"
  Conditions = [ """Transaction: xsso""", """PAM-CLNT-0023:""", """, Access/Protocol:""" ]
  Fields = ${PamParserTemplates.pam-authentication.Fields}[
    """({event_name}Executed 'sudo su' using transparent login)""",
  ]
}
```