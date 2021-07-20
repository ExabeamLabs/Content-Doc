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
    """evtTime"{0,20}:"({time}[^"]{1,2000})""",
    """agentHost"{0,20}:"({host}[^"]{1,2000})""",
    """repo"{0,20}:"({app}[^"]{1,2000})""",
    """reqUser"{0,20}:"({user}[^"]{1,2000})""",
    """access"{0,20}:"({activity}[^"]{1,2000})""",
    """reqData"{0,20}:"({additional_info}[^"]{1,2000})""",
    """resource"{0,20}:"({object}[^"\/]{1,2000})""",
    """resType"{0,20}:"({resource}[^"]{1,2000})""",
    """cliIP"{0,20}:"({src_ip}[^"]{1,2000})""",
    """cluster_name"{0,20}:"({dest_host}[^"]{1,2000})""",
  ]
}
```