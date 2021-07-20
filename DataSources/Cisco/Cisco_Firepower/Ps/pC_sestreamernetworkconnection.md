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
    """"sensor": "({host}[^"]{1,2000})"""",
    """"firewallRuleAction": "({action}[^"]{1,2000})"""",
    """"firewallRule": "({rule}[^"]{1,2000})"""",
    """"initiatorIpAddress": "({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"responderIpAddress": "({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"responderPort": ({dest_port}\d{1,100})""",
    """"clientApplication": "(Unknown|({network_app}[^"]{1,2000}))"""",
    """"transportProtocol": "({protocol}[^"]{1,2000})"""",
    """"initiatorTransmittedBytes": ({bytes_out}\d{1,100})""",
    """"responderTransmittedPackets": ({bytes_in}\d{1,100})""",
    """"ingressInterface": "({src_interface}[^"]{1,2000})"""",
    """"egressInterface": "({dest_interface}[^"]{1,2000})"""",
    """"user": "(No Authentication Required|(?i)Unknown|({user}[^"]{1,2000}))"""",
    """"recordTypeDescription": "({event_name}[^"]{1,2000})"""",
    """"clientUrl":[^\]]{1,2000}?"data": "({additional_info}[^"]{1,2000})"""",
    """"initiatorPort": ({src_port}\d{1,100})""",
  ]
}
```