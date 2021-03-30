#### Parser Content
```Java
{
Name = citrix-file-download
  DataType = "file-download"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""destinationServiceName=Citrix ShareFile""",""""Activity":"Download"""", """flexString1Label=application-action"""]
  Fields = ${CitrixParserTemplates.citrix-app-activity.Fields}[
  	""""Activity"+:"+({activity}[^"]+)"""",
    """"Date"+:"({time}[^"]+)""",
  ]
}
```