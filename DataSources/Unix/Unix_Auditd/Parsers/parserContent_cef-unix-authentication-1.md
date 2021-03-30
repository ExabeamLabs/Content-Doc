#### Parser Content
```Java
{
Name = cef-unix-authentication-1
  DataType = "authentication-successful"
  Conditions = [ """CEF""", """Unix|auditd""", """USER_AUTH""" ]
  Fields = ${UnixParserTemplates.cef-unix-template-1.Fields}[
    """CEF:([^\|]*\|){4}({event_name}[^|]+)\\""",
	]
}
```