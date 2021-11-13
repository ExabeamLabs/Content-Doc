#### Parser Content
```Java
{
Name = forcepoint-network-connection-successful-1
  DataType = "network-connection-successful"
  Conditions = [ """"New connection"""", """Action=""", """Event=""", """"Allow"""" ]

forcepoint-network-connection-template = {
  Vendor = Forcepoint
  Product = Forcepoint NGFW 
  Lms = ArcSight
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields=[
    """NodeId="({host}[\w.-]{1,2000})"""",
    """Timestamp="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Event="({additional_info}[^"]{1,2000})""",
    """Src="({src_ip}[A-Za-z\d.:]{1,2000})"""",
    """Dst="({dest_ip}[A-Za-z\d.:]{1,2000})"""",
    """Protocol="({protocol}[^"]{1,2000})""",
    """AccRxBytes="({bytes_in}\d{1,100})""",
    """AccTxBytes="({bytes_out}\d{1,100})""",
    """\WSport="({src_port}\d{1,100})""",
    """\WDport="({dest_port}\d{1,100})""",
    """RuleId="({rule_id}[^"]{1,2000})""",
    """InfoMsg="({failure_reason}[^"]{1,2000})""",
    """Situation="({activity}[^"]{1,2000})""",
    """Action="({action}[^"]{1,2000})""",
  ]
  DupFields = ["action->outcome"]
 
}
```