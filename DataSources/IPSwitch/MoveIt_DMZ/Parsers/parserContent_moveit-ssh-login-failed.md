#### Parser Content
```Java
{
Name = moveit-ssh-login-failed
  DataType = "authentication-failed"
  Conditions = [ """AgentBrand: MOVEit""", """FAILED: SSH"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """\sMessage:\s*({failure_reason}[^,\.]+)""",
  ]
}
```