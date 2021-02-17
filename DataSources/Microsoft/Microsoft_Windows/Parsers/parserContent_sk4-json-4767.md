#### Parser Content
```Java
{
Name = sk4-json-4767
  DataType = "windows-account-unlocked"
  Conditions = [""""event_id":4767""", """|Skyformation""", """Microsoft-Windows-Security-Auditing""", """A user account was unlocked"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A user account was unlocked)""",
  ]
}
```