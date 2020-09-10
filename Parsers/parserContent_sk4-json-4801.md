#### Parser Content
```Java
{
Name = sk4-json-4801
  DataType = "windows-4801"
  Conditions = [""""event_id":4801""", """|Skyformation""", """Microsoft-Windows-Security-Auditing""", """"The workstation was unlocked"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}The workstation was unlocked)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```