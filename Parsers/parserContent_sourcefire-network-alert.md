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
    """"connectionTimestamp":\s*({time}\d+)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"sensor":\s*"({host}[^"]+?)"""",
    """"sensor":\s*"[^"]+?\s+-\s+({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"sourcePortOrIcmpType":\s*({src_port}\d+)""",
    """"eventId":\s*({alert_id}[^",]+)""",
    """"message":\s*"({additional_info}[^"]+)""",
    """"recordTypeDescription":\s*"({alert_name}[^"]+)""",
    """"priority":\s*"({alert_severity}[^"]+)""",
    """"user":\s*"({user}[^"]+)""",
    """"destinationPortOrIcmpType":\s*({dest_port}\d+)""",
    """"transportProtocol":\s*"({protocol}[^"]+)""",
    """"sourceIpAddress":\s*"({src_ip}[A-Fa-f:\d.]+)""",
    """"destinationIpAddress":\s*"({dest_ip}[A-Fa-f:\d.]+)""",
    """({outcome}"blocked":\s*"Yes"),""",
    """"applicationProtocol":\s*"({app_protocol}[^"]+)""",
    """"classificationDescription":\s*"({alert_description}[^"]+)""",
    """"clientApplication":\s*"({process_name}[^"]+)""",
    """"idsPolicy":\s*"({policy}[^"]+)""",
    """"ruleId":\s*({rule_id}[^",]+)""",
    """"blockLength":\s*({bytes}\d+)""",
    """"recordType":\s*({record_type}[^",]+)""",
    """"iocNumber":\s*({ioc_number}[^",]+)""",
    """"sourceCountry":\s*({source_country}[^",]+)""",
    """"applicationId":\s*({application_id}[^",]+)""",
    """"blocked":\s*({blocked}[^",]+)""",
    """"connectionCounter":\s*({connection_counter}[^",]+)""",
    """"ipProtocolId":\s*({ip_protocol_id}[^",]+)""",
    """"destinationCountry":\s*({destination_country}[^",]+)""",
    """"ingressSecurityZone":\s*"({ingressSecurity_zone}[^"]+)""",
    """"ingressInterface":\s*"({ingress_interface}[^"]+)""",
    """"egressSecurityZone":\s*"({egress_security_zone}[^"]+)""",
    """"impactDescription":\s*"({impact}[^"]+)""",
    """"classificationName":\s*"({classification_name}[^"]+)""",
    """"blockType":\s*({block_type}[^",]+)""",
    """"deviceId":\s*({device_id}[^",\}]+)""",
    """"transportProtocol":\s*"({protocol}[^"]+)""",
    """"userId":\s*({user_id}\d+)""",
    """"firewallPolicy":\s*"({src_country}[^"]+)""",
    """"blocked":\s*"({blocked}[^"]+)""",
  ]
  DupFields = [ "host->sensor" ]
}
```