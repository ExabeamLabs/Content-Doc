#### Parser Content
```Java
{
Name = leef-eset-app-login-success
  DataType = "app-login"
  Conditions = [ """LEEF:""", """|ESET|RemoteAdministrator|""", """cat=ESET RA Audit Event""", """Native user login""", """result=Success""" ]
  Fields = ${ESETParserTemplates.eset-activity.Fields}[
  ]
}
```