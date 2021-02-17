#### Parser Content
```Java
{
Name = json-4672-1
  DataType = "windows-privileged-access"
  Conditions = [ """"event_id":4672""", """Special privileges assigned to new logon""" ]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}Special privileges assigned to new logon)""",
    """"hostname"+:"+(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}|({dest_host}[^"]+))""",
  ]
}
```