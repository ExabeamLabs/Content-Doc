#### Parser Content
```Java
{
Name = sk4-json-4725
  DataType = "windows-account-disabled"
  Conditions = [""""event_id":4725""", """|Skyformation""", """Microsoft-Windows-Security-Auditing""", """A user account was disabled"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A user account was disabled)""",
    """"hostname"+:"+(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}|({dest_host}[^"]+))""",
  ]
}
```