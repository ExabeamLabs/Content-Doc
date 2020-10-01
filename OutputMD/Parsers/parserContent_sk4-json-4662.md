#### Parser Content
```Java
{
Name = sk4-json-4662
  DataType = "object-access"
  Conditions = [""""event_id":4662""", """|Skyformation""", """Microsoft-Windows-Security-Auditing""", """An operation was performed on an object"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}An operation was performed on an object)""",
  ]
  DupFields = [ "host-> dest_host"]
}
```