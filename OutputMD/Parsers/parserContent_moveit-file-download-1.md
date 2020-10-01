#### Parser Content
```Java
{
Name = moveit-file-download-1
  DataType = "file-download"
  Conditions = [ """MOVEitDMZ""", """Download"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """\sFileID:\s*({file_id}[^,]+)""",
     """\sFileName:\s*({file_name}[^,]+)""",
     """\sFolderPath:\s*({file_path}[^,]+)""",
     """\sXFerSize:\s*({bytes}[^,]+)""",
     """({activity}Download)"""
  ]
}
```