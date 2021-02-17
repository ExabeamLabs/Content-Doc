#### Parser Content
```Java
{
Name = json-4723-2
  DataType = "windows-password-change"
  Conditions = ["""An attempt was made to change""", """computer_name""", """event_id\":4723"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}An attempt was made to change an account's password)""",
    """TargetUserName\\?"+:\\?"+({target_user}[^\\]+)\\?"""",
    """TargetDomainName\\?"+:\\?"+({target_domain}[^\s"\\]+)\\?"""",
    """"TargetSid\\?"+:\\?"+({target_user_sid}[^"\\]+)"""
  ]
  DupFields=[ "host->dest_host" ]
}
```