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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({host}[\w\.-]+)\s{1,100}SFIMS:""",
    """"host":"({host}[^"]+)""",
    """Protocol:\s{0,100}({protocol}[^,]+)""",
    """SrcIP:\s{0,100}({src_ip}[^,]+)""",
    """DstIP:\s{0,100}({dest_ip}[^,]+)""",
    """SrcPort:\s{0,100}({src_port}\d{1,100})""",
    """DstPort:\s{0,100}({dest_port}\d{1,100})""",
    """IngressInterface:\s{0,100}({ingress_interface}[^,]+)""",
    """EgressInterface:\s{0,100}({egress_interface}[^,]+)""",
    """IngressZone:\s{0,100}({ingress_zone}[^,]+)""",
    """EgressZone:\s{0,100}({egress_zone}[^,]+)""",
    """Policy:\s{0,100}({alert_type}[^,]+)""",
    """ConnectType:\s{0,100}({connect_type}[^,]+)""",
    """AccessControlRuleName:\s{0,100}({rule}[^,]+)""",
    """AccessControlRuleAction:\s{0,100}({outcome}[^,]+)""",
    """UserName:\s{0,100}(No Authentication Required|({user}[^,]+))""",
    """UserAgent:\s{0,100}({user_agent}.+?), Client:""",
    """UserAgent:\s{0,100}(Mozilla.+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """ApplicationProtocol:\s{0,100}({app_protocol}[^,]+)""",
    """WebApplication:\s{0,100}({web_application}[^,]+)""",
    """InitiatorPackets:\s{0,100}({initiator_packets}[^,]+)""",
    """ResponderPackets:\s{0,100}({responder_packets}[^,]+)""",
    """InitiatorBytes:\s{0,100}({bytes_in}\d{1,100})""",
    """ResponderBytes:\s{0,100}({bytes_out}\d{1,100})""",
    """NAPPolicy:\s{0,100}({nap_policy}[^,]+)""",
    """DNSResponseType:\s{0,100}({response_type}[^,]+)""",
    """ReferencedHost:\s{0,100}({dest_host}[\w\-.]+)""",
    """URL:\s{0,100}({full_url}[^\s"]+)""",
    """\W({log_type}Connect)Type:\s{0,100}({subtype}[^,]+?)(,|\s{0,100}$)""",
    """\WICMPType:\s{0,100}({icmp_type}[^,]+?)(,|\s{0,100}$)""",
    """\WICMPCode:\s{0,100}({icmp_code}\d)""",
    """\WTCPFlags:\s{0,100}({tcp_flags}[^,]+?)(,|\s{0,100}$)""",
    """\WURLCategory:\s{0,100}(Unknown|({category}[^,]+?))(,|\s{0,100}$)""",
    """\WURLReputation:\s{0,100}({reputation}[^,]+?)(,|\s{0,100}$)""",
  ]
  DupFields = [ "rule->alert_name", "user_agent->additional_info" ]
}
```