#### Parser Content
```Java
{
Name = moveit-member-added-2
  DataType = "member-added"
  Conditions = [ """MOVEitDMZ""", """Add Group Member"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """TargetName:\s+({target_user}[^,]+)""",
     """TargetID:\s+({target_user_sid}[^,]+)""",
     """({activity}Add Group Member)""",
     """\sID:\s({account_id}\d+)""",
  ]
}
```