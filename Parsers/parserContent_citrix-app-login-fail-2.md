#### Parser Content
```Java
{
Name = citrix-app-login-fail-2
  DataType = "app-login-fail"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """SkyFormation""","""Activity":"LoginLocked""","""flexString1Label=application-action""" ]
  Fields = ${CitrixParserTemplates.citrix-app-activity.Fields}[
    """"Date":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
  ]
}
```