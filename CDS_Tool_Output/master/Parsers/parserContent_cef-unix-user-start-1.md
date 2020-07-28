#### Parser Content
```Java
{
Name = cef-unix-user-start-1
  DataType = "remote-login"
  Conditions = [ """CEF""", """Unix|auditd""", """USER_START""" ]
  Fields = ${UnixParserTemplates.cef-unix-template-1.Fields}[
    """CEF:([^\|]*\|){4}({event_name}[^|]+)\\"""
    ]
}
```