#### Parser Content
```Java
{
Name = moveit-failed-logon-1
  DataType = "failed-logon"
  Conditions = [ """MOVEitDMZ""", """FAILED: Sign On"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """\sMessage:\s*({failure_reason}.+?)\s*$""",
  ]
}
```