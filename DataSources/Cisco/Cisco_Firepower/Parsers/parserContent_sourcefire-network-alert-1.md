#### Parser Content
```Java
{
Name = sourcefire-network-alert-1
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """IngressInterface:""", """Sinkhole:""", """ConnectType:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({host}[\w\.-]+)\s+SFIMS:""",
    """"host":"({host}[^"]+)""",
    """Protocol:\s*({protocol}[^,]+)""",
    """SrcIP:\s*({src_ip}[^,]+)""",
    """DstIP:\s*({dest_ip}[^,]+)""",
    """SrcPort:\s*({src_port}\d+)""",
    """DstPort:\s*({dest_port}\d+)""",
    """IngressInterface:\s*({ingress_interface}[^,]+)""",
    """EgressInterface:\s*({egress_interface}[^,]+)""",
    """IngressZone:\s*({ingress_zone}[^,]+)""",
    """EgressZone:\s*({egress_zone}[^,]+)""",
    """Policy:\s*({alert_type}[^,]+)""",
    """ConnectType:\s*({connect_type}[^,]+)""",
    """AccessControlRuleName:\s*({rule}[^,]+)""",
    """AccessControlRuleAction:\s*({outcome}[^,]+)""",
    """UserName:\s*(No Authentication Required|({user}[^,]+))""",
    """UserAgent:\s*({user_agent}.+?), Client:""",
    """UserAgent:\s*(Mozilla.+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """ApplicationProtocol:\s*({app_protocol}[^,]+)""",
    """WebApplication:\s*({web_application}[^,]+)""",
    """InitiatorPackets:\s*({initiator_packets}[^,]+)""",
    """ResponderPackets:\s*({responder_packets}[^,]+)""",
    """InitiatorBytes:\s*({bytes_in}\d+)""",
    """ResponderBytes:\s*({bytes_out}\d+)""",
    """NAPPolicy:\s*({nap_policy}[^,]+)""",
    """DNSResponseType:\s*({response_type}[^,]+)""",
    """ReferencedHost:\s*({dest_host}[\w\-.]+)""",
    """URL:\s*({full_url}[^\s"]+)""",
    """\W({log_type}Connect)Type:\s*({subtype}[^,]+?)(,|\s*$)""",
    """\WICMPType:\s*({icmp_type}[^,]+?)(,|\s*$)""",
    """\WICMPCode:\s*({icmp_code}\d)""",
    """\WTCPFlags:\s*({tcp_flags}[^,]+?)(,|\s*$)""",
    """\WURLCategory:\s*(Unknown|({category}[^,]+?))(,|\s*$)""",
    """\WURLReputation:\s*({reputation}[^,]+?)(,|\s*$)""",
  ]
  DupFields = [ "rule->alert_name", "user_agent->additional_info" ]
}
```