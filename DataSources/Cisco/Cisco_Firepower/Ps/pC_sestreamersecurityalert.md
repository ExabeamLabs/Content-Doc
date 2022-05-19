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
    """"connectionTimestamp":\s{0,100}({time}\d{1,100})""",
    """"sensor":\s{0,100}"({host}[^"]{1,2000})"""",
    """"sourceIpAddress":\s{0,100}"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"destinationIpAddress":\s{0,100}"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"fileSize":\s{0,100}({bytes}\d{1,100})""",
    """"recordTypeDescription":\s{0,100}"({alert_name}[^"]{1,2000})"""",
    """"filePolicy":\s{0,100}"({rule}[^"]{1,2000})"""",
    """"destinationPort":\s{0,100}({dest_port}\d{1,100})""",
    """"sourcePort":\s{0,100}({src_port}\d{1,100})""",
    """"clientApplication":\s{0,100}"({process}[^"]{1,2000})"""",
    """"shaHash":\s{0,100}"({md5}[^"]{1,2000})"""",
    """"uri":.+?"data":\s{0,100}"({malware_url}[^"]{1,2000})"""",
    """"fileName":.+?"data":\s{0,100}"({malware_file_name}[^"]{1,2000})"""",
    """"direction":\s{0,100}({direction}[^,]{1,2000}),""",
    """"fileType":\s{0,100}"({file_type}[^"]{1,2000})"""",
    """"user":\s{0,100}"(No Authentication Required|Unknown|({user}[^"]{1,2000}))"""",
    """"disposition"{1,20}:\s{0,100}({outcome}\d{1,100})""",
    """"disposition"{1,20}:\s{0,100}"{1,20}(N\/A|Unknown|({additional_info}[^"]{1,2000}))"""",
    """"threatScore"{1,20}:\s{0,100}({alert_severity}\d{1,100})""",
    """"recordType"{1,20}:\s{0,100}({record_type}\d{1,100})"""
  ]
  DupFields = [ "alert_name->alert_type" , "process->process_name"]


}
```