#### Parser Content
```Java
{
Name = cef-unix-process-1
  DataType = "process-created"
  Conditions = [ """CEF""", """Unix|auditd""", """SYSCALL""" ]
  Fields = ${UnixParserTemplates.cef-unix-template-1.Fields}[
    """CEF:([^\|]*\|){5}({event_name}[^\\\|]+)\|({outcome}[^\|]+)"""
    ]
}
```