#### Parser Content
```Java
{
Name = sk4-workday-app-login
  DataType = "app-login"
  Conditions = [ """sk4-login-success""","""cat=access""","""workday"""]
  Fields = ${WorkdayParserTemplates.sk4-workday-login-template.Fields}[]
}
```