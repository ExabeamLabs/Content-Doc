#### Parser Content
```Java
{
Name = airwatch-authentication
  DataType = "authentication-successful" 
  Conditions = [ """AirWatch""", """Event Category:"Authentication"""", """Event:""""]
  Fields = ${AirWatchParserTemplates.airwatch-auth-activity.Fields}[]
  DupFields = ["event_type->auth_type"]
}
```