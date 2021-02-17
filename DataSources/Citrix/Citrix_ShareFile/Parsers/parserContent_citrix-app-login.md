#### Parser Content
```Java
{
Name = citrix-app-login
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""destinationServiceName=Citrix ShareFile""",""""Activity":"Login"""", """flexString1Label=application-action"""]
  Fields = ${CitrixParserTemplates.citrix-app-activity.Fields}[
  	""""Activity"+:"+({activity}[^"]+)"""",
    """"Date"+:"({time}[^"]+)""",
  ]
}
```