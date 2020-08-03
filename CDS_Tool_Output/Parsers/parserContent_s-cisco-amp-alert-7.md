#### Parser Content
```Java
{
Name = s-cisco-amp-alert-7
  Conditions = [ """"event_type"""", """"Executed malware"""", """"trajectory":""", """"timestamp_nanoseconds":""" ]
}

${CiscoParsersTemplates.s-cisco-amp-alert} {
  Name = s-cisco-amp-alert-8
  Conditions = [ """"event_type"""", """"Critical Fault Raised"""", """"trajectory":""", """"timestamp_nanoseconds":""" ]
}

${CiscoParsersTemplates.s-cisco-amp-alert} {
  Name = s-cisco-amp-alert-9
  Conditions = [ """"event_type"""", """"Major Fault Raised"""", """"trajectory":""", """"timestamp_nanoseconds":""" ]
}

${CiscoParsersTemplates.s-cisco-amp-alert} {
  Name = s-cisco-amp-alert-10
  Conditions = [ """"event_type"""", """"Cloud IOC""", """"trajectory":""", """"timestamp_nanoseconds":""" ]
}

${CiscoParsersTemplates.s-cisco-amp-alert} {
  Name = s-cisco-amp-alert-11
  Conditions = [ """"event_type"""", """"Policy Update Failure"""", """"trajectory":""", """"timestamp_nanoseconds":""" ]
}

${CiscoParsersTemplates.s-cisco-amp-alert} {
  Name = s-cisco-amp-alert-13
  Conditions = [ """"event_type"""", """Security Alert Detected""", """"trajectory":""", """"timestamp_nanoseconds":""", """THREAT_DETECTION""" ]
}

${CiscoParsersTemplates.s-cisco-amp-alert} {
  Name = s-cisco-amp-alert-14
  Conditions = [ """"event_type"""", """"Cloud Recall Detection of False Negative"""", """"trajectory":""", """"timestamp_nanoseconds":""" ]
}

${CiscoParsersTemplates.s-cisco-amp-alert} {
  Name = s-cisco-amp-alert-15
  Conditions = [ """"event_type"""", """"Multiple Infected Files"""", """"trajectory":""", """"timestamp_nanoseconds":""" ]
}

{
  Name = s-estreamer-security-alert
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """"protocol":""", """"recordType": 502,""", """blockLength""", """"recordTypeDescription":""" ]
  Fields = [
    """"connectionTimestamp":\s*({time}\d+)""",
    """"sensor":\s*"({host}[^"]+)"""",
    """"sourceIpAddress":\s*"({src_ip}[A-Fa-f:\d.]+)""",
    """"destinationIpAddress":\s*"({dest_ip}[A-Fa-f:\d.]+)""",
    """"fileSize":\s*({bytes}\d+)""",
    """"recordTypeDescription":\s*"({alert_name}[^"]+)"""",
    """"filePolicy":\s*"({rule}[^"]+)"""",
    """"destinationPort":\s*({dest_port}\d+)""",
    """"sourcePort":\s*({src_port}\d+)""",
    """"clientApplication":\s*"({process}[^"]+)"""",
    """"shaHash":\s*"({md5}[^"]+)"""",
    """"uri":.+?"data":\s*"({malware_url}[^"]+)"""",
    """"fileName":.+?"data":\s*"({malware_file_name}[^"]+)"""",
    """"direction":\s*({direction}[^,]+),""",
    """"fileType":\s*"({file_type}[^"]+)"""",
    """"user":\s*"(No Authentication Required|Unknown|({user}[^"]+))"""",
    """"disposition"+:\s*"+(N\/A|({additional_info}[^"]+))"""",
    """"threatScore"+:\s*({alert_severity}\d+)""",
    """"recordType"+:\s*({record_type}\d+)"""
  ]
  DupFields = [ "alert_name->alert_type" , "process->process_name"]
}
```