#### Parser Content
```Java
{
Name = securelink-login-failed
  DataType = "failed-app-login"
  Conditions = [  """Login failed:""", """SecureLink:""", """User:""" ]
  Fields = ${SecureLinkParserTemplates.securelink-events.Fields}[
  """({event_name}Login failed):\s({failure_reason}[^.]{1,2000})""" 
  ]
}
```