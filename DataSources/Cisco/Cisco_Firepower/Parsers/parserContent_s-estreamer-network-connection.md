#### Parser Content
```Java
{
Name = s-estreamer-network-connection
  Vendor = Cisco 
  Product = Cisco Firepower
  Lms = Splunk
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"protocol":""", """"recordType": 71,""", """"eventType":""", """"recordTypeDescription":""" ]
  Fields = [
    """"eventDateTime":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"sensor":\s*"({host}[^"]+)"""",
    """"firewallRuleAction":\s*"({action}[^"]+)"""",
    """"firewallRule":\s*"({rule}[^"]+)"""",
    """"initiatorIpAddress":\s*"({src_ip}[A-Fa-f:\d.]+)""",
    """"responderIpAddress":\s*"({dest_ip}[A-Fa-f:\d.]+)""",
    """"responderPort":\s*({dest_port}\d+)""",
    """"clientApplication":\s*"({network_app}[^"]+)"""",
    """"transportProtocol":\s*"({protocol}[^"]+)"""",
    """"initiatorTransmittedBytes":\s*({bytes_out}\d+)""",
    """"responderTransmittedPackets":\s*({bytes_in}\d+)""",
    """"ingressInterface":\s*"({src_interface}[^"]+)"""",
    """"egressInterface":\s*"({dest_interface}[^"]+)"""",
    """"user":\s*"(No Authentication Required|({user}[^"]+))"""",
    """"recordTypeDescription":\s*"({event_name}[^"]+)"""",
    """"recordTypeCategory":\s"({log_type}[^"]+)"""",
    """"clientUrl":.+?"data":\s*"({additional_info}[^"]+)"""",
    """"initiatorPort":\s+({src_port}\d+)""",
  ]
}
```