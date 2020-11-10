#### Parser Content
```Java
{
Name = json-4724-1
  DataType = "windows-password-reset"
  Conditions = [ """An attempt was made to reset an account's password""", """computer_name""", """event_id\":4724""" ]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}An attempt was made to reset an account's password)""",
    """TargetUserName\\?"+:\\?"({target_user}[^\\]+)\\?"""",
    """TargetDomainName\\?"+:\\?"({target_domain}[^\s\\]+)\\?"""",
    """"TargetSid\\?"+:\\?"({target_user_sid}[^\\]+)"""
  ]
  DupFields=[ "host->dest_host" ]
}
```