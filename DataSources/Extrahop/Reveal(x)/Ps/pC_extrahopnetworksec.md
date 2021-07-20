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
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}-\d{1,100}:\d{1,100})\s{0,100}({host}[^\s]{1,2000})""",
     """"description":"({additional_info}[^"]{1,2000})""", 
     """"ipaddrs":\["({src_ip}[A-Fa-f:\d.]{1,2000}).+?offender""",
     """"ipaddrs":\["({dest_ip}[A-Fa-f:\d.]{1,2000}).+?victim""",
     """"dnsNames":\["({src_host}[^."]{1,2000})(\.({domain}[^"]{1,2000}))?".+?offender""",
     """"dnsNames":\["({dest_host}[^."]{1,2000})(\.({domain}[^"]{1,2000}))?".+?victim""",
     """"title":"({alert_name}[^"]{1,2000})""",
     """"netbiosName":(null|"({sub_domain}[^"]{1,2000}))""",
     """"dnsNames":\["({query}[^"]{1,2000})"\]""",
     """"status":(null|"({status}[^"\s]{1,2000}))""",
     """"riskScore":(null|({alert_severity}\d{1,100}))""",
]
  DupFields = ["alert_name->alert_type"]
}
```