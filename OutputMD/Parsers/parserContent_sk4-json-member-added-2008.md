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
```