#### Parser Content
```Java
{
Name = json-4726
  DataType = "windows-account-deleted"
  Conditions = [ """A user account was deleted""", """computer_name""", """event_id\":4726""" ]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}A user account was deleted)""",
    """TargetUserName\\?"+:\\?"({target_user}[^\\]+)\\?"""",
    """TargetDomainName\\?"+:\\?"({target_domain}[^\s"\\]+)\\?"""",
    """"TargetSid\\?"+:\\?"({target_user_sid}[^"\\]+)"""
  ]
  DupFields=[ "host->dest_host", "target_user->account_name" ]
}
```