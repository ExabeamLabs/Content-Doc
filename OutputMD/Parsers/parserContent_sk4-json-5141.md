#### Parser Content
```Java
{
Name = sk4-json-5141
  DataType = "ds-access"
  Conditions = [""""event_id":5141""", """|Skyformation""", """Microsoft-Windows-Security-Auditing""", """"A directory service object was deleted"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A directory service object was deleted)""",
    """"+ObjectClass"+:"+({object_class}[^"]+)""",
    """"+DSType"+:"+({service_type}[^"]+)""",
    
  ]
   DupFields = [ "host->dest_host" ]
}
```