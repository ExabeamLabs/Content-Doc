#### Parser Content
```Java
{
Name = ad-json-member-added-2008
  DataType = "windows-ds-access"
  Conditions = [""""event_id":""", """Microsoft-Windows-Security-Auditing""", """A member was added to a security-enabled"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A member was removed from a security-enabled)""",
    """event_id"+:({event_code}\d+)""",
    """"+MemberSid"+:"+({account_id}[^"]+)""",
    """"TargetSid":"({group_id}[^\s"]+)"""
  ]
}
```