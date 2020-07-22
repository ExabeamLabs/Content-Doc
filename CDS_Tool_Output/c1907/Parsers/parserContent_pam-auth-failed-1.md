#### Parser Content
```Java
{
Name = pam-auth-failed-1
  DataType = "authentication-failed"
  Conditions = [ """Transaction: login""", """PAM-CMN-0900:""", """gkpsyslog""" ]
  Fields = ${PamParserTemplates.pam-authentication.Fields}[
    """({event_name}Bad User ID)""",
  ]
  DupFields = [ "event_name->failure_reason" ]
}
```