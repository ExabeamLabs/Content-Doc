#### Parser Content
```Java
{
Name = s-mssql-database-login-failed
  DataType = "database-failed-login"
  Conditions = [ """EventCode=33205""", """action_id:LGIF""" ]
  Fields = ${MicrosoftParserTemplates.s-mssql-database-login.Fields} [
    """\Wstatement:({failure_reason}[^.]+)"""
  ]
}
```