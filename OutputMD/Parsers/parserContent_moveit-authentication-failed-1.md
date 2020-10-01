#### Parser Content
```Java
{
Name = moveit-authentication-failed-1
  DataType = "authentication-failed"
  Conditions = [ """MOVEitDMZ""", """authentication failed"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """\sMessage:\s*({failure_reason}[^,\."]+)""",
  ]
}
```