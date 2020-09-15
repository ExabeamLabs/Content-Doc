#### Parser Content
```Java
{
Name = moveit-authentication-successful-1
  DataType = "authentication-successful"
  Conditions = [ """MOVEitDMZ""", """Signed on"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """\sMessage:\s*({additional_info}.+?)\s*$""",
  ]
}
```