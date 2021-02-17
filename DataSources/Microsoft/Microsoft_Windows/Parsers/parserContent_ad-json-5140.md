#### Parser Content
```Java
{
Name = ad-json-5140
  DataType = "windows-ds-access"
  Conditions = [""""event_id":5140""", """Microsoft-Windows-Security-Auditing""", """A network share object was accessed"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A network share object was accessed)""",
	"""AccessList"+:"+({accesses}[^"\\]+)""",
	"""ShareName"+:"+\\+.\\+({share_name}[^"\\]+)""",
	""""+ObjectType"+:"+({file_type}[^"]+)"""
  ]
   DupFields = ["host->dest_host"]
}
```