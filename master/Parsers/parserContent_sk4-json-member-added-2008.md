#### Parser Content
```Java
{
Name = sk4-json-member-added-2008
  DataType = "windows-member-added"
  Conditions = [""""event_id":4728""", """|Skyformation""", """Microsoft-Windows-Security-Auditing""", """A member was added to a security-enabled"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A member was added to a security-enabled)""",
    """"+MemberName"+:"+CN\\=({account_dn}[^,]+)""",
    """"+MemberSid"+:"+({account_id}[^"]+)""",

  ]
   DupFields = [ "host->dest_host" ]
}
${WinParserTemplates.json-windows-events-1}{
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