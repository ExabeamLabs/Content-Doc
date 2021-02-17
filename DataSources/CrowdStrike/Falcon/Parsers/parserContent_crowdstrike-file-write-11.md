#### Parser Content
```Java
{
Name = crowdstrike-file-write-11
  DataType = "file-write"
  Conditions = [ """"event_simpleName\":\"PdfFileWritten\"""", """"@timestamp"""" ]
  Fields = ${CrowdStrikeParserTemplates.crowdstrike-auth-activity.Fields} [
  ]
}
```