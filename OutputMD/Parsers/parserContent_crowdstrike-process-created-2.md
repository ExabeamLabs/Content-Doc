#### Parser Content
```Java
{
Name = crowdstrike-process-created-2
  DataType = "process-created"
  Conditions = [ """"event_simpleName\":\"SyntheticProcessRollup2\"""", """"@timestamp"""" ]
  Fields = ${CrowdStrikeParserTemplates.crowdstrike-auth-activity.Fields} [
  ]
}
```