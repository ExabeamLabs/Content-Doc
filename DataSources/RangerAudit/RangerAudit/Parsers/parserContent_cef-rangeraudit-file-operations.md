#### Parser Content
```Java
{
Name = cef-rangeraudit-file-operations
  Vendor = RangerAudit
  Product = RangerAudit
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """"RangerAudit"""", """resType""", """"path"""" ]
  Fields = [
    """evtTime"{0,20}:"({time}[^"]+)""",
    """agentHost"{0,20}:"({host}[^"]+)""",
    """repo"{0,20}:"({app}[^"]+)""",
    """reqUser"{0,20}:"({user}[^"]+)""",
    """access"{0,20}:"({accesses}[^"]+)""",
    """resource"{0,20}:"({file_path}[^"]+)""",
    """action"{0,20}:"({action}[^"]+)""",
    """cliIP"{0,20}:"({src_ip}[^"]+)""",
    """cluster_name"{0,20}:"({dest_host}[^"]+)""",
  ]
}
```