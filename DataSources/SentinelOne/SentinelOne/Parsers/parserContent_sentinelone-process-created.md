#### Parser Content
```Java
{
Name = sentinelone-process-created
  DataType = "process-created"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """processCreation {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}processCreation)""",
    """\scommandLine:\s{0,100}\\?"\s{0,100}({command_line}.+?)\s{0,100}"\\n""",
    """parent.*?path:\s{0,100}\\?"{1,20}\s{0,100}({parent_process}({parent_process_directory}[^@]{1,2000}?)[\\\/]{0,2000}({parent_process_name}[^"\\\/]{1,2000}))\\*".*commandLine:\s{0,100}\\?"{1,20}\s{0,100}({parent_command_line}.+?)"\\n?""",
    """\sparent[^\}]{1,2000}?value:\s"{0,20}({parent_process_guid}[^"]{1,2000})"""
  ]
}
```