#### Parser Content
```Java
{
Name = cef-microsoft-graph-activity
  DataType = "failed-app-login"
  Conditions = [ """appDisplayName":""", """"src-endpoint":"Graph Sign-In logs"""","""failureReason":""", """event-name":"login-failed""" ]
  Fields = ${MSParserTemplates.cef-o365-app-login.Fields} [
    """"+status"+.+?failureReason":"+({failure_reason}[^"]+)""",
  ]
}
```