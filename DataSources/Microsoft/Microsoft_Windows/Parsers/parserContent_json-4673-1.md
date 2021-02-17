#### Parser Content
```Java
{
Name = json-4673-1
  DataType = "windows-privileged-access"
  Conditions = [ """"event_id":4673""", """A privileged service was called""" ]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A privileged service was called)""",
    """"PrivilegeList"+:"+({privileges}[^"]+)""",
    """"ObjectServer"+:"+({object_server}[^"]+)""",
    """"ProcessName"+:"+({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?))"""",
    """"ProcessId"+:"+({pid}[^"]+)""",
    """"hostname"+:"+(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}|({dest_host}[^"]+))""",
  ]
}
```