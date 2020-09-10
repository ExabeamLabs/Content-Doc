#### Parser Content
```Java
{
Name = json-4738-1
  DataType = "windows-password-change"
  Conditions = [ """"event_id":4738""", """A user account was changed""" ]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A user account was changed)""",
    """"TargetSid"+:"+({target_user_sid}[^"]+)""",
    """"TargetDomainName"+:"+({target_domain}[^"]+)""",
  ]
}
```