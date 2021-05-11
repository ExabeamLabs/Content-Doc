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
    """"eventDateTime": "({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"sensor": "({host}[^"]+)"""",
    """"firewallRuleAction": "({action}[^"]+)"""",
    """"firewallRule": "({rule}[^"]+)"""",
    """"initiatorIpAddress": "({src_ip}[A-Fa-f:\d.]+)""",
    """"responderIpAddress": "({dest_ip}[A-Fa-f:\d.]+)""",
    """"responderPort": ({dest_port}\d{1,100})""",
    """"clientApplication": "(Unknown|({network_app}[^"]+))"""",
    """"transportProtocol": "({protocol}[^"]+)"""",
    """"initiatorTransmittedBytes": ({bytes_out}\d{1,100})""",
    """"responderTransmittedPackets": ({bytes_in}\d{1,100})""",
    """"ingressInterface": "({src_interface}[^"]+)"""",
    """"egressInterface": "({dest_interface}[^"]+)"""",
    """"user": "(No Authentication Required|(?i)Unknown|({user}[^"]+))"""",
    """"recordTypeDescription": "({event_name}[^"]+)"""",
    """"clientUrl":[^\]]+?"data": "({additional_info}[^"]+)"""",
    """"initiatorPort": ({src_port}\d{1,100})""",
  ]
}
```