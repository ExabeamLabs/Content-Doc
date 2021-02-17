#### Parser Content
```Java
{
Name = json-4722
  DataType = "windows-account-enabled"
  Conditions = ["""A user account was enabled""", """computer_name""", """event_id\":4722"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}A user account was enabled)""",
    """TargetUserName\\?"+:\\?"({target_user}[^\\]+)\\?"""",
    """TargetDomainName\\?"+:\\?"({target_domain}[^\\]+)\\?"""",
    """"TargetSid\\?"+:\\?"({target_user_sid}[^\\]+)"""
  ]
}
```