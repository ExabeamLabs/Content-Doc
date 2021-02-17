#### Parser Content
```Java
{
Name = ad-json-4722
  DataType = "windows-ds-access"
  Conditions = [""""event_id":4722""", """Microsoft-Windows-Security-Auditing""", """A user account was enabled"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A user account was enabled)""",
  ]
}
```