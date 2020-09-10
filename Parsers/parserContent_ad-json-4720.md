#### Parser Content
```Java
{
Name = ad-json-4720
  DataType = "windows-ds-access"
  Conditions = [""""event_id":4720""", """Microsoft-Windows-Security-Auditing""", """A user account was created"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A user account was created)""",
  ]
   DupFields = ["host->dest_host"]
}
```