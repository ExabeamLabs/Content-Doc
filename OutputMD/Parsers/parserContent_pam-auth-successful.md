#### Parser Content
```Java
{
Name = pam-auth-successful
  DataType = "authentication-successful"
  Conditions = [ """Transaction: login""", """logged in successfully""", """PAM-CMN-0917:""", """gkpsyslog""" ]
  Fields = ${PamParserTemplates.pam-authentication.Fields}[
    """({event_name}logged in successfully via ldap authentication.)""",
  ]
}
```