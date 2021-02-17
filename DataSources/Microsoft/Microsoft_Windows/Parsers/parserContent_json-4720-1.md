#### Parser Content
```Java
{
Name = json-4720-1
  DataType = "windows-account-created"
  Conditions = [ """A user account was created""", """event_id\":4720""", """computer_name""" ]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}A user account was created)""",
    """TargetSid\\?"+:\\?"+({account_id}[^"\\]+)""",
    """TargetUserName\\?"+:\\?"+({account_name}[^"\\]+)""",
    """TargetDomainName\\?"+:\\?"+({account_domain}[^"\\]+)""",
    """(\\+t)+'({user_type}[^']+)'\s*-\s*Enabled"""
 ]
 DupFields = ["host->dest_host"]
}
```