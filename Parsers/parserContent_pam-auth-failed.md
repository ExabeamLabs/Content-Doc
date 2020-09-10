#### Parser Content
```Java
{
Name = pam-auth-failed
  DataType = "authentication-failed"
  Conditions = [ """Transaction: login""", """PAM-CMN-2179:""", """gkpsyslog""" ]
  Fields = ${PamParserTemplates.pam-authentication.Fields}[
    """({event_name}LDAP authentication failed)""",
    """({failure_reason}The user entered an incorrect password.)""",
  ]
}
```