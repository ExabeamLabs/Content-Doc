#### Parser Content
```Java
{
Name = cef-unix-user-login-1
  DataType = "remote-logon"
  Conditions = [ """CEF""", """Unix|auditd""", """LOGIN""" ]
  Fields = ${UnixParserTemplates.cef-unix-template-1.Fields}[
    """CEF:([^\|]*\|){4}({event_name}[^|]+)\\"""
    ]
}
```