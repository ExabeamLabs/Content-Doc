#### Parser Content
```Java
{
Name = sk4-workday-failed-app-login
  DataType = "failed-app-login"
  Conditions = [ """sk4-login-failure""","""cat=access""","""workday"""]
  Fields = ${WorkdayParserTemplates.sk4-workday-login-template.Fields}[
    """reason=({failure_reason}[^"]+)\srequest""",
  ]
}
```