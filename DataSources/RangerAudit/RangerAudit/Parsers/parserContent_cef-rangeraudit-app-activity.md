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
    """evtTime"*:"({time}[^"]+)""",
    """agentHost"*:"({host}[^"]+)""",
    """repo"*:"({app}[^"]+)""",
    """reqUser"*:"({user}[^"]+)""",
    """access"*:"({activity}[^"]+)""",
    """reqData"*:"({additional_info}[^"]+)""",
    """resource"*:"({object}[^"\/]+)""",
    """resType"*:"({resource}[^"]+)""",
    """cliIP"*:"({src_ip}[^"]+)""",
    """cluster_name"*:"({dest_host}[^"]+)""",
  ]
}
```