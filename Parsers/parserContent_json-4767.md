#### Parser Content
```Java
{
Name = json-4767
  DataType = "windows-account-unlocked"
  Conditions = ["""A user account was unlocked""", """Account Name:""", """computer_name""", """event_id\":4767"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}A user account was unlocked)""",
    """TargetSid\\?"+:\\?"({user_sid}[^\\]+)\\?"""",
    """TargetUserName\\?"+:\\?"({target_user}[^\\]+)\\?"""",
    """TargetDomainName\\?"+:\\?"({target_domain}[^\s"\\]+)\\?""""
  ]
}
```