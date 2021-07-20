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
    """evtTime"{0,20}:"({time}[^"]{1,2000})""",
    """agentHost"{0,20}:"({host}[^"]{1,2000})""",
    """repo"{0,20}:"({app}[^"]{1,2000})""",
    """reqUser"{0,20}:"({user}[^"]{1,2000})""",
    """access"{0,20}:"({accesses}[^"]{1,2000})""",
    """resource"{0,20}:"({file_path}[^"]{1,2000})""",
    """action"{0,20}:"({action}[^"]{1,2000})""",
    """cliIP"{0,20}:"({src_ip}[^"]{1,2000})""",
    """cluster_name"{0,20}:"({dest_host}[^"]{1,2000})""",
  ]
}
```