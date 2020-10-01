#### Parser Content
```Java
{
Name = crowdstrike-modify-binary
  DataType = "file-operations"
  Conditions = [ """event_simpleName""", """ModifyServiceBinary""" ]
  Fields = ${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp.Fields} [
    """"ServiceImagePath":"({file_path}({file_parent}[^"]*?\\+)({file_name}[^\\\s"]+?\.({file_ext}[^\\\s"\.]+?)))(\s|")"""
    """"ServiceObjectName":"({additional_info}[^"]+)"""
    """({accesses}Modify)"""
  ]
}
```