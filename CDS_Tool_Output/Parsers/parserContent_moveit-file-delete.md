#### Parser Content
```Java
{
Name = moveit-file-delete
  DataType = "file-delete"
  Conditions = [ """AgentBrand: MOVEit""", """Delete File"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """\sFileID:\s*({file_id}[^,]+)""",
     """\sFileName:\s*({file_name}[^,]+)""",
     """\sFolderPath:\s*({file_path}[^,]+)""",
     """\sXFerSize:\s*({bytes}[^,]+)""",
  ]
}
```