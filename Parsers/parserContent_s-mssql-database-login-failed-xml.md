#### Parser Content
```Java
{
Name = s-mssql-database-login-failed-xml
  Lms = Direct
  DataType = "database-failed-login"
  Conditions = [ """>33205</EventID>""", """action_id:LGIF""" ]
  Fields = ${MicrosoftParserTemplates.s-mssql-database-login.Fields} [
    """\Wstatement:({failure_reason}[^.]+)"""
  ]
}
```