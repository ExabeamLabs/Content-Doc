#### Parser Content
```Java
{
Name = forcepoint-network-connection-successful
  Product = Forcepoint NGFW
  DataType = "network-connection-successful"
  Conditions = [ """CEF:""", """|FORCEPOINT|""", """|Connection_Allowed|""" ]
  Fields = ${ForcepointParserTemplates.forcepoint-template.Fields} [
    """proto=\s{0,100}({protocol}.+?)(\s\w+=)""",
    ]

forcepoint-template = {
  Vendor = Forcepoint
  Product = Forcepoint
  Lms = ArcSight
  TimeFormat = "epoch"
  Fields=[
    """CEF:\s{1,100}\d{1,100}\|([^\|]{1,2000}\|){4}({activity}[^\|]{1,2000})""",
    """ahost=\s{0,100}({host}.+?)(\s\w+=)""",
    """\Wrt=({time}\d{1,100})""",
    """src=\s{0,100}({src_ip}[A-Za-z\d.:]{1,2000})""".
    """dhost=\s{0,100}({dest_host}.+?)(\s\w+=)""",
    """dst=\s{0,100}({dest_ip}.+?)(\s\w+=)""",
    """amac=\s{0,100}({mac}.+?)(\s\w+=)""",
    """dvc=\s{0,100}({src_host}.+?)(\s\w+=)""",
    """app=\s{0,100}({protocol}.+?)(\s\w+=)""",
    """\Win=({bytes_in}\d{1,100})""",
    """\Wout=({bytes_out}\d{1,100})""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\sdeviceInboundInterface=({src_interface}.+?)\s{0,100}\w+=""",
    """\sdeviceOutboundInterface=({dest_interface}.+?)\s{0,100}\w+=""",
    """\sproto=({protocol}.+?)\s{0,100}\w+=""",
    ]
 },
 forcepoint-template-1= {
  Vendor = Forcepoint
  Product = Forcepoint NGFW
  Lms = Splunk
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Fields=[
    """\Wrt=({time}\w{3}\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """dvchost=({host_ip}[A-Fa-f\d:.]{1,2000})""",
    """act=({action}[^=]{1,2000})\s\w{1,100}=""",
    """src=({src_ip}[A=Fa-f\d:.]{1,2000})""",
    """dst=({dest_ip}[A=Fa-f\d:.]{1,2000})""",
    """spt=({src_port}\d{1,1000})""",
    """dpt=({dest_port}\d{1,1000})""",
    """proto=({protocol}[^=]{1,2000}?)\s\w{1,100}=""",
    """CEF:([^|]{0,2000}\|){4}({event_code}[^|]{1,2000}?)\|({event_name}[^|]{1,2000})\|""",
    """msg=({additional_info}[^"]{1,2000}?)\s{1,100}\w{1,100}=""",
    """\Wout=({bytes_out}\d{1,100})""",
    """\Win=({bytes_in}\d{1,100})""",
    """deviceInboundInterface=({src_interface}[^=]{1,2000})\s\w{1,100}=""",
    """deviceOutboundInterface=({dest_interface}[^=]{1,2000})\s\w{1,100}="""
    ]
 }
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