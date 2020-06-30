#### Parser Content
```Java
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
    """"fileName":.+?"data":\s*"({file_name}[^"]+)"""",
    """"direction":\s*({direction}[^,]+),""",
    """"fileType":\s*"({file_type}[^"]+)"""",
    """"user":\s*"(No Authentication Required|({user}[^"]+))"""",
  ]
  DupFields = [ "alert_name->alert_type" , "process->process_name"]
}
```