#### Parser Content
```Java
{
Name = crowdstrike-file-operations-1
  DataType = "file-operations"
  Conditions = [ """"event_simpleName":"File""", """Info"""" ]
  Fields = ${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp.Fields} [
  """"id":"({alert_id}[\w-]+?)""""
  """"name":"({alert_name}[^"]+?)""""
  """"File({accesses}Delete|Open|Rename)"""
  ]
}
```