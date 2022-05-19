#### Parser Content
```Java
{
Name = cisco-ftd-permit-any
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Syslog
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """%FTD-""", """Permit Any""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]{1,2000})\s{0,100}%FTD-""",
    """%FTD-({priority}\d{1,100})-({event_code}\d{1,100})\\?""",
    """({event_name}Permit Any)""",
    """AccessControlRuleAction="{1,20}({outcome}[^"]{1,2000})"{1,20}""",
    """SrcIP="{1,20}({src_ip}[^"]{1,2000})"{1,20}""",
    """DstIP="{1,20}({dest_ip}[^"]{1,2000})"{1,20}""",
    """SrcPort="{1,20}({src_port}[^"]{1,2000})"{1,20}""",
    """DstPort="{1,20}({dest_port}[^"]{1,2000})"{1,20}""",
    """\sProtocol="{1,20}({protocol}[^"]{1,2000})"{1,20}""",
    """IngressInterface="{1,20}({ingress_interface}[^"]{1,2000})"{1,20}""",
    """EgressInterface="{1,20}({egress_interface}[^"]{1,2000})"{1,20}""",
    """DeviceUUID="{1,20}({device_id}[^"]{1,2000})"{1,20}""",
    """Client="{1,20}({app}[^"]{1,2000})"{1,20}""",
    """ApplicationProtocol="{1,20}({app_protocol}[^"]{1,2000})"{1,20}""",
    """InitiatorBytes="{1,20}({bytes_in}[^"]{1,2000})"{1,20}""",
    """ResponderBytes="{1,20}({bytes_out}[^"]{1,2000})"{1,20}""",
    """NAPPolicy="{1,20}({nap_policy}[^"]{1,2000})"{1,20}""",
    """URL="{1,20}({full_url}[^"]{1,2000})"{1,20}""",
    """InitiatorPackets="{1,20}({initiator_packets}[^"]{1,2000})"{1,20}""",
    """ResponderPackets="{1,20}({responder_packets}[^"]{1,2000})"{1,20}""",
    """User="{1,20}(No Authentication Required|({user}[^"]{1,2000}))"{1,20}""",
  ]
  DupFields = [ "outcome->action" ]


}
```