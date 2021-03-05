#### Parser Content
```Java
{
Name = citrix-app-login-fail-2
  DataType = "app-login-fail"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """SkyFormation""","""Activity":"LoginLocked""","""flexString1Label=application-action""" ]
  Fields = ${CitrixParserTemplates.citrix-app-activity.Fields}[
  ]
}
```