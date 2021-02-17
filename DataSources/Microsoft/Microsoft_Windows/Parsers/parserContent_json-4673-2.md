#### Parser Content
```Java
{
Name = json-4673-2
  DataType = "windows-privileged-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"EventID":"4673"""", """A privileged service was called""" ]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A privileged service was called)""",
    """({event_code}4673)""",
    """"TimeCreated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"Computer":"({host}[^"]+)""""
    """"PrivilegeList":"({privileges}[^"]+)""",
    """"ObjectServer":"({object_server}[^"]+)""",
    """"ProcessName":"({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?))"""",
    """"ProcessId":"({pid}[^"]+)"""
  ]
   DupFields = ["host->dest_host","directory->process_directory"]
}
```