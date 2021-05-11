#### Parser Content
```Java
{
Name = sourcefire-network-alert
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """"connectionTimestamp":""", """"applicationProtocol":""", """"securityZoneEgressUuid":""" ]
  Fields = [
    """"connectionTimestamp":\s{0,100}({time}\d{10})""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"sensor":\s{0,100}"({host}[^"]+?)"""",
    """"sensor":\s{0,100}"[^"]+?\s{1,100}-\s{1,100}({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"sourcePortOrIcmpType":\s{0,100}({src_port}\d{1,100})""",
    """"eventId":\s{0,100}({alert_id}[^",]+)""",
    """"message":\s{0,100}"({additional_info}[^"]+)""",
    """"recordTypeDescription":\s{0,100}"({alert_name}[^"]+)""",
    """"priority":\s{0,100}"({alert_severity}[^"]+)""",
    """"user":\s{0,100}"(?:Unknown|No Authentication Required|({user}[^"]+))""",
    """"destinationPortOrIcmpType":\s{0,100}({dest_port}\d{1,100})""",
    """"transportProtocol":\s{0,100}"({protocol}[^"]+)""",
    """"sourceIpAddress":\s{0,100}"({src_ip}[A-Fa-f:\d.]+)""",
    """"destinationIpAddress":\s{0,100}"({dest_ip}[A-Fa-f:\d.]+)""",
    """({outcome}"blocked":\s{0,100}"Yes"),""",
    """"applicationProtocol":\s{0,100}"(Unknown|({app_protocol}[^"]+))""",
    """"classificationDescription":\s{0,100}"({alert_description}[^"]+)""",
    """"clientApplication":\s{0,100}"(Unknown|({process_name}[^"]+))""",
    """"idsPolicy":\s{0,100}"({policy}[^"]+)""",
    """"ruleId":\s{0,100}({rule_id}[^",]+)""",
    """"blockLength":\s{0,100}({bytes}\d{1,100})""",
    """"recordType":\s{0,100}({record_type}[^",]+)""",
    """"iocNumber":\s{0,100}({ioc_number}[^",]+)""",
    """"sourceCountry":\s{0,100}({source_country}[^",]+)""",
    """"applicationId":\s{0,100}({application_id}[^",]+)""",
    """"blocked":\s{0,100}({blocked}[^",]+)""",
    """"connectionCounter":\s{0,100}({connection_counter}[^",]+)""",
    """"ipProtocolId":\s{0,100}({ip_protocol_id}[^",]+)""",
    """"destinationCountry":\s{0,100}({destination_country}[^",]+)""",
    """"ingressSecurityZone":\s{0,100}"(N\/A|({ingressSecurity_zone}[^"]+))""",
    """"ingressInterface":\s{0,100}"(N\/A|({ingress_interface}[^"]+))""",
    """"egressSecurityZone":\s{0,100}"(N\/A|({egress_security_zone}[^"]+))""",
    """"impactDescription":\s{0,100}"({impact}[^"]+)""",
    """"classificationName":\s{0,100}"({classification_name}[^"]+)""",
    """"blockType":\s{0,100}({block_type}[^",]+)""",
    """"deviceId":\s{0,100}({device_id}[^",\}]+)""",
    """"transportProtocol":\s{0,100}"({protocol}[^"]+)""",
    """"userId":\s{0,100}({user_id}\d{1,100})""",
    """"firewallPolicy":\s{0,100}"({src_country}[^"]+)""",
    """"blocked":\s{0,100}"({blocked}[^"]+)""",
  ]
  DupFields = [ "host->sensor", "classification_name->alert_type"]
}
```