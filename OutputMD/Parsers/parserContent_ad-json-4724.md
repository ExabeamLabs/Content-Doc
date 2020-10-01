#### Parser Content
```Java
{
Name = ad-json-4724
  DataType = "windows-password-reset"
  Conditions = [""""event_id":4724""", """Microsoft-Windows-Security-Auditing""", """An attempt was made to reset an account's password"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}An attempt was made to reset an account's password)""",
  ]
}
```