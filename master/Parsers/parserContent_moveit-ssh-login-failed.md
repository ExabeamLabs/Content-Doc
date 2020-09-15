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
${MoveITParserTemplates.moveit-activity}{
  Name = moveit-failed-logon-1
  DataType = "failed-logon"
  Conditions = [ """MOVEitDMZ""", """FAILED: Sign On"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """\sMessage:\s*({failure_reason}.+?)\s*$""",
  ]
}
```