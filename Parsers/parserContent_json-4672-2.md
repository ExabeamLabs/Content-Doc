#### Parser Content
```Java
{
Name = json-4672-2
  DataType = "windows-privileged-access"
  Conditions = ["""Special privileges assigned to new logon""", """Privileges""", """computer_name""", """event_id\":4672"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}Special privileges assigned to new logon)""",
    """PrivilegeList\\?"+:\\?"({privileges}[^"]+?)\\?""""
  ]
  DupFields=[ "host->dest_host" ]
}
```