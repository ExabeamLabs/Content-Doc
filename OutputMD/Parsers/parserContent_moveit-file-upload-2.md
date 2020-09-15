#### Parser Content
```Java
{
Name = moveit-file-upload-2
DataType = "file-upload"
  Conditions = [ """MOVEitDMZ""", """Send"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """\sFileID:\s*({file_id}[^,]+)""",
     """\sFileName:\s*({file_name}[^,]+)""",
     """\sFolderPath:\s*({file_path}[^,]+)""",
     """\sXFerSize:\s*({bytes}[^,]+)""",
     """({activity}Send)""",
     """TargetName:\s({user_fullname}[^,]+)"""
     """Parm2:\s({user_email}[^@]+@[^\.]+\.[^,]+)"""
  ]
}
```