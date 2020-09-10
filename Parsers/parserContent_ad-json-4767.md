#### Parser Content
```Java
{
Name = ad-json-4767
  DataType = "windows-privileged-access"
  Conditions = [""""event_id":4767""", """Microsoft-Windows-Security-Auditing""", """A user account was unlocked"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A user account was unlocked)""",
  ]
}
```