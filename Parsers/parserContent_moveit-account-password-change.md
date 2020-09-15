#### Parser Content
```Java
{
Name = moveit-account-password-change
  DataType = "password-change"
  Conditions = [ """MOVEitDMZ""", """Change User Password"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """TargetName:\s+({target_user}[^,]+)""",
     """TargetID:\s+({target_user_sid}[^,]+)""",
     """({activity}Change User Password)"""
  ]
}
```