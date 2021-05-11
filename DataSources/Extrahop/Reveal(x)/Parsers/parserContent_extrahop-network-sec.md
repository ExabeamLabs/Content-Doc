#### Parser Content
```Java
{
Name = extrahop-network-sec
  Vendor = Extrahop
  Product = Reveal(x)
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS-SS:SS"
  Conditions = [ """categories""", """sec.""", """vendor":"ExtraHop""", """description""","""title"""]
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
     """"status":(null|"({status}[^"\s]+))""",
     """"riskScore":(null|({alert_severity}\d{1,100}))""",
]
  DupFields = ["alert_name->alert_type"]
}
```