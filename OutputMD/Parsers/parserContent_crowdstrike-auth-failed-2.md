#### Parser Content
```Java
{
Name = crowdstrike-auth-failed-2
  DataType = "authentication-failed"
  Conditions = [ """"event_simpleName\":\"UserLogonFailed\"""", """"@timestamp"""" ]
  Fields = ${CrowdStrikeParserTemplates.crowdstrike-auth-activity.Fields} [
  ]
}
```