#### Parser Content
```Java
{
Name = cef-unix-exe-1
  DataType = "process-created"
  Conditions = [ """CEF""", """Unix|auditd""", """EXECVE""" ]
  Fields = ${UnixParserTemplates.cef-unix-template-1.Fields}[
    """CEF:([^\|]*\|){4}({event_name}[^|]+)\\""",
    """Arguments:\s*({command_line}.*?)\s*cs1Label="""
	]
}
```