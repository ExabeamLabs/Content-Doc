#### Parser Content
```Java
{
Name = sk4-json-5137
  DataType = "windows-ds-access"
  Conditions = [""""event_id":5137""", """|Skyformation""", """Microsoft-Windows-Security-Auditing""", """A directory service object was created"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A directory service object was created)""",
    """"+ObjectClass"+:"+({object_class}[^"]+)""",
    """"+DSType"+:"+({service_type}[^"]+)""",
    """"+OpCorrelationID"+:"+({correlation_id}[^"]+)""",
    """"+ObjectDN"+:"+({object_dn}[^"]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```