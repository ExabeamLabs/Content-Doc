#### Parser Content
```Java
{
Name = sk4-json-member-removed-2008
  DataType = "windows-member-removed"
  Conditions = [ """|Skyformation""", """Microsoft-Windows-Security-Auditing""", """A member was removed from a security-enabled"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A member was removed from a security-enabled)""",
    """"event_id":({event_code}\d+)""",
    """"+group"+:.+?name"+:"+({group_name}[^"]+)""",
    """"+group"+:.+?domain"+:"+({group_domain}[^"]+)""",
    """"+MemberSid"+:"+({account_id}[^"]+)""",
    """"+MemberName"+:"+CN\\=({account_id}[^,"]+)""",
    """"+MemberName"+:"+CN\\=({account_dn}[^,"]+)""",
  ]
}
```