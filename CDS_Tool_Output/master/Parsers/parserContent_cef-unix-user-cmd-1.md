#### Parser Content
```Java
{
Name = cef-unix-user-cmd-1
  DataType = "process-created"
  Conditions = [ """CEF""", """Unix|auditd""", """USER_CMD""" ]
  Fields = ${UnixParserTemplates.cef-unix-template-1.Fields}[
    """cmd\\=({command}[^\s]+)""",
    """CEF:([^\|]*\|){4}({event_name}[^|]+)\\"""
    ]
}
```