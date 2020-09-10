#### Parser Content
```Java
{
Name = ad-json-4740
  DataType = "windows-account-lockout"
  Conditions = [""""event_id":4740""", """Microsoft-Windows-Security-Auditing""", """Account That Was Locked Out"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}Account That Was Locked Out)""",
  ]
}
```