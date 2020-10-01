#### Parser Content
```Java
{
Name = moveit-member-added-1
  DataType = "member-added"
  Conditions = [ """MOVEitDMZ""", """Add User"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """TargetName:\s+({target_user}[^,]+)""",
     """TargetID:\s+({target_user_sid}[^,]+)""",
     """({activity}Add User)""",
     """\sID:\s({account_id}\d+)""",
  ]
}
```