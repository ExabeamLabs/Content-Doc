#### Parser Content
```Java
{
Name = crowdstrike-file-process-alert-2
  DataType = "file-operations"
  Conditions = [ """"event_simpleName\":\"LsassHandleFromUnsignedModule\"""", """"@timestamp"""" ]
  Fields = ${CrowdStrikeParserTemplates.crowdstrike-auth-activity.Fields} [
    """event_simpleName\\":\\"({alert_name}[^"\\]+)""",
  ]
}
```