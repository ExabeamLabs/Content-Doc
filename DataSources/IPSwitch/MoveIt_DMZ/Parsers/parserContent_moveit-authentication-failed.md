#### Parser Content
```Java
{
Name = moveit-authentication-failed
  DataType = "authentication-failed"
  Conditions = [ """AgentBrand: MOVEit""", """authentication failed"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """\sMessage:\s*({failure_reason}[^,\."]+)""",
  ]
}
```