#### Parser Content
```Java
{
Name = sentinelone-process-created
  DataType = "process-created"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """processCreation {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}processCreation)""",
    """\scommandLine:\s*\\?"\s*({command_line}.+?)\s*"\\n""",
    """parent.*?path:\s*\\?"+\s*({parent_process}({parent_process_directory}[^@]+?)[\\\/]*({parent_process_name}[^"\\\/]+))\\*".*commandLine:\s*\\?"+\s*({parent_command_line}.+?)"\\n?""",
    """\sparent[^\}]+?value:\s"*({parent_process_guid}[^"]+)"""
  ]
}
```