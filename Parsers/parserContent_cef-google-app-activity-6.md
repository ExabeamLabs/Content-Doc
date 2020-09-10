#### Parser Content
```Java
{
Name = cef-google-app-activity-6
  Conditions = [ """CEF:""", """|Skyformation|""", """"applicationName":"token"""", """"uniqueQualifier":""", """flexString1=activity""", """flexString1Label=application-action""" ]
  Fields = ${GoogleParserTemplates.cef-google-app-activity.Fields} [
    """"events":.*?"name":"method_name"[^\}]+?"value":"({activity}[^"]+?)""""
  ]
}
```