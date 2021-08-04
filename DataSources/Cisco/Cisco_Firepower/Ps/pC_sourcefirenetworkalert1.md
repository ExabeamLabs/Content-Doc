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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({host}[\w\.-]{1,2000})\s{1,100}SFIMS:""",
    """"host":"({host}[^"]{1,2000})""",
    """Protocol:\s{0,100}({protocol}[^,]{1,2000})""",
    """SrcIP:\s{0,100}({src_ip}[^,]{1,2000})""",
    """DstIP:\s{0,100}({dest_ip}[^,]{1,2000})""",
    """SrcPort:\s{0,100}({src_port}\d{1,100})""",
    """DstPort:\s{0,100}({dest_port}\d{1,100})""",
    """IngressInterface:\s{0,100}({ingress_interface}[^,]{1,2000})""",
    """EgressInterface:\s{0,100}({egress_interface}[^,]{1,2000})""",
    """IngressZone:\s{0,100}({ingress_zone}[^,]{1,2000})""",
    """EgressZone:\s{0,100}({egress_zone}[^,]{1,2000})""",
    """Policy:\s{0,100}({alert_type}[^,]{1,2000})""",
    """ConnectType:\s{0,100}({connect_type}[^,]{1,2000})""",
    """AccessControlRuleName:\s{0,100}({rule}[^,]{1,2000})""",
    """AccessControlRuleAction:\s{0,100}({outcome}[^,]{1,2000})""",
    """UserName:\s{0,100}(No Authentication Required|({user}[^,]{1,2000}))""",
    """UserAgent:\s{0,100}({user_agent}.+?), Client:""",
    """UserAgent:\s{0,100}(Mozilla.+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """ApplicationProtocol:\s{0,100}({app_protocol}[^,]{1,2000})""",
    """WebApplication:\s{0,100}({web_application}[^,]{1,2000})""",
    """InitiatorPackets:\s{0,100}({initiator_packets}[^,]{1,2000})""",
    """ResponderPackets:\s{0,100}({responder_packets}[^,]{1,2000})""",
    """InitiatorBytes:\s{0,100}({bytes_in}\d{1,100})""",
    """ResponderBytes:\s{0,100}({bytes_out}\d{1,100})""",
    """NAPPolicy:\s{0,100}({nap_policy}[^,]{1,2000})""",
    """DNSResponseType:\s{0,100}({response_type}[^,]{1,2000})""",
    """ReferencedHost:\s{0,100}({dest_host}[\w\-.]{1,2000})""",
    """URL:\s{0,100}({full_url}[^\s"]{1,2000})""",
    """\W({log_type}Connect)Type:\s{0,100}({subtype}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """\WICMPType:\s{0,100}({icmp_type}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """\WICMPCode:\s{0,100}({icmp_code}\d)""",
    """\WTCPFlags:\s{0,100}({tcp_flags}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """\WURLCategory:\s{0,100}(Unknown|({category}[^,]{1,2000}?))(,|\s{0,100}$)""",
    """\WURLReputation:\s{0,100}({reputation}[^,]{1,2000}?)(,|\s{0,100}$)""",
  ]
  DupFields = [ "rule->alert_name", "user_agent->additional_info" ]
}
```