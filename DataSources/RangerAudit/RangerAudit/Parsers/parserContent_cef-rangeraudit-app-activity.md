#### Parser Content
```Java
{
Name = cef-rangeraudit-app-activity
  Vendor = RangerAudit
  Product = RangerAudit
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """"RangerAudit"""", """enforcer""", """"yarn-acl"""" ]
  Fields = [
    """evtTime"{0,20}:"({time}[^"]+)""",
    """agentHost"{0,20}:"({host}[^"]+)""",
    """repo"{0,20}:"({app}[^"]+)""",
    """reqUser"{0,20}:"({user}[^"]+)""",
    """access"{0,20}:"({activity}[^"]+)""",
    """reqData"{0,20}:"({additional_info}[^"]+)""",
    """resource"{0,20}:"({object}[^"\/]+)""",
    """resType"{0,20}:"({resource}[^"]+)""",
    """cliIP"{0,20}:"({src_ip}[^"]+)""",
    """cluster_name"{0,20}:"({dest_host}[^"]+)""",
  ]
}
```