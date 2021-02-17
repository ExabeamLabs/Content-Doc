#### Parser Content
```Java
{
Name = leef-eset-web-activity-denied
  DataType = "web-activity"
  Conditions = [ """LEEF:""", """|ESET|RemoteAdministrator|""", """cat=ESET Filtered Website Event""", """actionTaken=blocked""" ]
  Fields = ${ESETParserTemplates.eset-activity.Fields}[
  ]
}
```