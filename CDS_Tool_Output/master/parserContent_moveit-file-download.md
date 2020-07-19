#### Parser Content
```Java
{
Name = moveit-file-download
  DataType = "file-download"
  Conditions = [ """AgentBrand: MOVEit""", """Download"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """\sFileID:\s*({file_id}[^,]+)""",
     """\sFileName:\s*({file_name}[^,]+)""",
     """\sFolderPath:\s*({file_path}[^,]+)""",
     """\sXFerSize:\s*({bytes}[^,]+)""",
  ]
}
```