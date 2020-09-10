#### Parser Content
```Java
{
Name = pam-remote-logon
  DataType = "remote-logon"
  Conditions = [ """Transaction: connection""", """connected to""", """Idle time out:""" ]
  Fields = ${PamParserTemplates.pam-authentication.Fields}[
    """({event_name}connected to)""",
  ]
}
```