#### Parser Content
```Java
{
Name = moveit-file-upload-1
DataType = "file-upload"
  Conditions = [ """MOVEitDMZ""", """Upload"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """\sFileID:\s*({file_id}[^,]+)""",
     """\sFileName:\s*({file_name}[^,]+)""",
     """\sFolderPath:\s*({file_path}[^,]+)""",
     """\sXFerSize:\s*({bytes}[^,]+)""",
     """({activity}Upload)""",
  ]
}
```