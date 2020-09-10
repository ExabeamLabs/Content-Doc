#### Parser Content
```Java
{
Name = sk4-json-4724
  DataType = "windows-password-reset"
  Conditions = [""""event_id":4724""", """|Skyformation""", """Microsoft-Windows-Security-Auditing""", """An attempt was made to reset an account's password"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}An attempt was made to reset an account's password)""",
  ]
   DupFields=[ "host->dest_host" ]
}
${WinParserTemplates.json-windows-events-1}{
  Name = ad-json-4724
  DataType = "windows-password-reset"
  Conditions = [""""event_id":4724""", """Microsoft-Windows-Security-Auditing""", """An attempt was made to reset an account's password"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}An attempt was made to reset an account's password)""",
  ]
}
```