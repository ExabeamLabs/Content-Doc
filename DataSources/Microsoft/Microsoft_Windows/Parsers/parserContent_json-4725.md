#### Parser Content
```Java
{
Name = json-4725
  DataType = "windows-account-disabled"
  Conditions = [ """A user account was disabled""", """event_id\":4725""", """computer_name""" ]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}A user account was disabled)""",
    """"TargetSid\\?"+:\\?"+({target_user_sid}[^"\\]+)""",
    """"TargetDomainName\\?"+:\\?"+({target_domain}[^"\\]+)""",
    """"TargetUserName\\?"+:\\?"+({target_user}[^"\\]+)"""
  ]
  DupFields=[ "host->dest_host" ]
}
```