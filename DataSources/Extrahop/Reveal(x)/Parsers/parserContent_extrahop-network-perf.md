#### Parser Content
```Java
{
Name = extrahop-network-perf
  Vendor = Extrahop
  Product = Reveal(x)
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS-SS:SS"
  Conditions = ["""categories""",  """perf.""", """vendor":"ExtraHop""", """dnsNames""", """netbiosName"""]
  Fields = [
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}-\d{1,100}:\d{1,100})\s{0,100}({host}[^\s]+)""",
     """"description":"({additional_info}[^"]+)""",
     """"ipaddrs":\["({src_ip}[A-Fa-f:\d.]+).+?offender""",
     """"ipaddrs":\["({dest_ip}[A-Fa-f:\d.]+).+?victim""",
     """"dnsNames":\["({src_host}[^."]+)(\.({domain}[^"]+))?".+?offender""",
     """"dnsNames":\["({dest_host}[^."]+)(\.({domain}[^"]+))?".+?victim""",
     """"title":"({alert_name}[^"]+)""",
     """"netbiosName":(null|"({sub_domain}[^"]+))""",
     """"dnsNames":\["({query}[^"]+)"\]""",
     """"status":(null|"({status}[^"]+))""",
     """"riskScore":(null|"({alert_severity}[^"]+))""",
]
  DupFields = ["alert_name->alert_type"]
}
```