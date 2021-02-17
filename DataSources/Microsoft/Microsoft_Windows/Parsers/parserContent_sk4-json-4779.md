#### Parser Content
```Java
{
Name = sk4-json-4779
  DataType = "windows-4779"
  Conditions = [""""event_id":4779""", """|Skyformation""", """Microsoft-Windows-Security-Auditing""", """"A session was disconnected from a Window Station"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}"A session was disconnected from a Window Station)""",
  ]
}
```