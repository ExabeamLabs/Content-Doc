#### Parser Content
```Java
{
Name = cef-sentinelone-security-alert-2
  Product = SentinelOne
  DataType = "process-created"
  Conditions = [ """CEF:""", """|Security|SentinelOne|""", """|process|""" ]
  Fields = ${SentinelOneParserTemplates.cef-sentinelone-security-alert.Fields}[
    """\suser:(|(({domain}[^\\\/]+)[\\\/]+)?(SYSTEM|({user}[^\\\/"]+?)))(\s+\w+:|\s*$)""",
    """\sprocessCmd:"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+?))\s*"""",
    """\ssha256:(|({sha256_sum}.+?))(\s+\w+:|\s*$)""",
    """parentProcessName:({parent_process_name}[^:"]+?)\s+\w+:""",
  ]
  DupFields = ["directory->process_directory"]
}
```