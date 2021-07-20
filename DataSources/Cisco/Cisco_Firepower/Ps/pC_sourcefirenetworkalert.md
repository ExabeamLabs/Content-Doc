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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"sensor":\s{0,100}"({host}[^"]{1,2000}?)"""",
    """"sensor":\s{0,100}"[^"]{1,2000}?\s{1,100}-\s{1,100}({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"sourcePortOrIcmpType":\s{0,100}({src_port}\d{1,100})""",
    """"eventId":\s{0,100}({alert_id}[^",]{1,2000})""",
    """"message":\s{0,100}"({additional_info}[^"]{1,2000})""",
    """"recordTypeDescription":\s{0,100}"({alert_name}[^"]{1,2000})""",
    """"priority":\s{0,100}"({alert_severity}[^"]{1,2000})""",
    """"user":\s{0,100}"(?:Unknown|No Authentication Required|({user}[^"]{1,2000}))""",
    """"destinationPortOrIcmpType":\s{0,100}({dest_port}\d{1,100})""",
    """"transportProtocol":\s{0,100}"({protocol}[^"]{1,2000})""",
    """"sourceIpAddress":\s{0,100}"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"destinationIpAddress":\s{0,100}"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """({outcome}"blocked":\s{0,100}"Yes"),""",
    """"applicationProtocol":\s{0,100}"(Unknown|({app_protocol}[^"]{1,2000}))""",
    """"classificationDescription":\s{0,100}"({alert_description}[^"]{1,2000})""",
    """"clientApplication":\s{0,100}"(Unknown|({process_name}[^"]{1,2000}))""",
    """"idsPolicy":\s{0,100}"({policy}[^"]{1,2000})""",
    """"ruleId":\s{0,100}({rule_id}[^",]{1,2000})""",
    """"blockLength":\s{0,100}({bytes}\d{1,100})""",
    """"recordType":\s{0,100}({record_type}[^",]{1,2000})""",
    """"iocNumber":\s{0,100}({ioc_number}[^",]{1,2000})""",
    """"sourceCountry":\s{0,100}({source_country}[^",]{1,2000})""",
    """"applicationId":\s{0,100}({application_id}[^",]{1,2000})""",
    """"blocked":\s{0,100}({blocked}[^",]{1,2000})""",
    """"connectionCounter":\s{0,100}({connection_counter}[^",]{1,2000})""",
    """"ipProtocolId":\s{0,100}({ip_protocol_id}[^",]{1,2000})""",
    """"destinationCountry":\s{0,100}({destination_country}[^",]{1,2000})""",
    """"ingressSecurityZone":\s{0,100}"(N\/A|({ingressSecurity_zone}[^"]{1,2000}))""",
    """"ingressInterface":\s{0,100}"(N\/A|({ingress_interface}[^"]{1,2000}))""",
    """"egressSecurityZone":\s{0,100}"(N\/A|({egress_security_zone}[^"]{1,2000}))""",
    """"impactDescription":\s{0,100}"({impact}[^"]{1,2000})""",
    """"classificationName":\s{0,100}"({classification_name}[^"]{1,2000})""",
    """"blockType":\s{0,100}({block_type}[^",]{1,2000})""",
    """"deviceId":\s{0,100}({device_id}[^",\}]{1,2000})""",
    """"transportProtocol":\s{0,100}"({protocol}[^"]{1,2000})""",
    """"userId":\s{0,100}({user_id}\d{1,100})""",
    """"firewallPolicy":\s{0,100}"({src_country}[^"]{1,2000})""",
    """"blocked":\s{0,100}"({blocked}[^"]{1,2000})""",
  ]
  DupFields = [ "host->sensor", "classification_name->alert_type"]
}
```