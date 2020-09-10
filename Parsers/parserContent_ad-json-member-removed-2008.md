#### Parser Content
```Java
{
Name = ad-json-member-removed-2008
  DataType = "windows-ds-access"
  Conditions = [""""event_id":""", """Microsoft-Windows-Security-Auditing""", """A member was removed from a security-enabled"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A member was removed from a security-enabled)""",
    """"+MemberSid"+:"+({account_id}[^"]+)""",
    """"TargetSid":"({group_id}[^\s"]+)"""
    """event_id"+:({event_code}\d+)""",
  ]
}
```