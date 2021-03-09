#### Parser Content
```Java
{
Name = crowdstrike-process-created-1
  DataType = "process-created"
  Conditions = [ """"event_simpleName\":\"ProcessRollup2\"""", """"@timestamp"""" ]
  Fields = ${CrowdStrikeParserTemplates.crowdstrike-auth-activity.Fields} [
        """"ImageFileName\\*":\\*"({process}[^"\\]+\/*({process_name}[^"\\]+))""",
        """"ImageFileName\\*":\\*"({process}[^"]+\\({process_name}[^"\\]+))""",
  ]
}
```