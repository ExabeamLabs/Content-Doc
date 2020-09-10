#### Parser Content
```Java
{
Name = crowdstrike-auth-failed-1
  DataType = "authentication-failed"
  Conditions = [ """"event_simpleName\":\"UserLogonFailed2\"""", """"@timestamp"""" ]
  Fields = ${CrowdStrikeParserTemplates.crowdstrike-auth-activity.Fields} [
  ]
}
```