#### Parser Content
```Java
{
Name = moveit-failed-logon
  DataType = "failed-logon"
  Conditions = [ """AgentBrand: MOVEit""", """FAILED: Sign On"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """\sMessage:\s*({failure_reason}[^,\."]+)""",
  ]
}
```