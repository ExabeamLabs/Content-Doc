#### Parser Content
```Java
{
Name = cef-edirectory-security-alert
  DataType = "alert"
  Conditions = [ """CEF:""", """|eDirectory|eDirectory|""", """|INTRUDER_DETECTED|""" ]
  Fields = ${eDirectoryParserTemplates.cef-edirectory-events.Fields} [
    """CEF:([^\|]*\|){5}({alert_name}[^\|]+)""",
    """CEF:([^\|]*\|){6}({alert_severity}[^\|]+)""",
    """sproc=({process_name}.*?)\s\w+=""", 
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```