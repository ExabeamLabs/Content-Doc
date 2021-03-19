#### Parser Content
```Java
{
Name = sentinelone-process-created
  DataType = "process-created"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """processCreation {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}processCreation)""",
    """\scommandLine:\s*"+(?:\\*)"+({command_line}[^"\\]+)""",
    """parent.*?path:\s+\\?"+({parent_process}({parent_process_directory}[^"]+?)[\\\/]*({parent_process_name}[^"\\\/]+))\\*"""",
    """\sparent[^\}]+?value:\s"*({parent_process_guid}[^"]+)"""
  ]
}
```