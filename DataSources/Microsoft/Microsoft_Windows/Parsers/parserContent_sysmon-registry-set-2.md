#### Parser Content
```Java
{
Name = sysmon-registry-set-2
  Conditions = [ """Registry value set: """, """ UtcTime: """ ]
  DataType = "file-operations"
  Fields = ${MicrosoftParserTemplates.sysmon-process-events.Fields}[
    """\s+Image:\s*({file_path}({file_parent}(?:(\w+:)?[^:]+)?[\\\/])?({file_name}.+?))\s+\w+:""",
    """TargetObject:\s*({object}.+?)\s+(\w+:|$)"""
  ]
}
```