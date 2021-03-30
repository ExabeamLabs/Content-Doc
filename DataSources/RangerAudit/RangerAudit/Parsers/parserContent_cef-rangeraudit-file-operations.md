#### Parser Content
```Java
{
Name = cef-rangeraudit-file-operations
  Vendor = RangerAudit 
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """"RangerAudit"""", """resType""", """"path"""" ]
  Fields = [
    """evtTime"*:"({time}[^"]+)""",
    """agentHost"*:"({host}[^"]+)""",
    """repo"*:"({app}[^"]+)""",
    """reqUser"*:"({user}[^"]+)""",
    """access"*:"({accesses}[^"]+)""",
    """resource"*:"({file_path}[^"]+)""",
    """action"*:"({action}[^"]+)""",
    """cliIP"*:"({src_ip}[^"]+)""",
    """cluster_name"*:"({dest_host}[^"]+)""",
  ]
}
```