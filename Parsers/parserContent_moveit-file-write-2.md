#### Parser Content
```Java
{
Name = moveit-file-write-2
  DataType = "file-write"
  Conditions = [ """MOVEitDMZ""", """Rename"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
    """({activity}Rename)"""
  ]
}
```