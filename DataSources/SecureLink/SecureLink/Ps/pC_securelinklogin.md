#### Parser Content
```Java
{
Name = securelink-login
  DataType = "app-login"
  Conditions = [  """ Logged in.""", """SecureLink:""", """User:""" ]
  Fields = ${SecureLinkParserTemplates.securelink-events.Fields}[
  """({event_name}Logged in)"""
  ]
}
```