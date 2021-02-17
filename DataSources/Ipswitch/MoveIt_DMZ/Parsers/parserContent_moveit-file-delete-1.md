#### Parser Content
```Java
{
Name = moveit-file-delete-1
  DataType = "file-delete"
  Conditions = [ """MOVEitDMZ""", """Delete File"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """\sFileID:\s*({file_id}[^,]+)""",
     """\sFileName:\s*({file_name}[^,]+)""",
     """\sFolderPath:\s*({file_path}[^,]+)""",
     """\sXFerSize:\s*({bytes}[^,]+)""",
     """({activity}Delete)"""
  ]
}
```