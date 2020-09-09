#### Parser Content
```Java
{
Name = sk4-json-4800
  DataType = "windows-4800"
  Conditions = [""""event_id":4800""", """|Skyformation""", """Microsoft-Windows-Security-Auditing""", """"The workstation was locked"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}The workstation was locked)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```