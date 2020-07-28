#### Parser Content
```Java
{
Name = moveit-file-upload
  DataType = "file-upload"
  Conditions = [ """AgentBrand: MOVEit""", """Upload"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """\sFileID:\s*({file_id}[^,]+)""",
     """\sFileName:\s*({file_name}[^,]+)""",
     """\sFolderPath:\s*({file_path}[^,]+)""",
     """\sXFerSize:\s*({bytes}[^,]+)""",
  ]
}
```