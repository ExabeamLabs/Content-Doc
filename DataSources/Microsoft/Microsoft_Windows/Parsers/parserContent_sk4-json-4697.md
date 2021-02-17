#### Parser Content
```Java
{
Name = sk4-json-4697
  DataType = "windows-privileged-access"
  Conditions = [""""event_id":4697""", """|Skyformation""", """Microsoft-Windows-Security-Auditing""", """A service was installed in the system"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A service was installed in the system)""",
    """"+ServiceType"+:"+({service_type}[^"]+)""",
    """"+ServiceName"+:"+({service_name}[^"]+)""",
    """"+ServiceFileName"+:"+({process}({directory}[^\s]+)\\({process_name}[^"]+))""",
    """"+ServiceStartType"+:"+({service_start_type}[^"]+)"""
  ]
   DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```