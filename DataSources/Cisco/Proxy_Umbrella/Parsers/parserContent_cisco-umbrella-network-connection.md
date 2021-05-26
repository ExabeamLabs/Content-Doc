#### Parser Content
```Java
{
Name = cisco-umbrella-network-connection
  Vendor = Cisco
  Product = Proxy Umbrella
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """destinationServiceName=Cisco Umbrella """, """dproc=IP """, """"identity":"""" ]
  Fields = [
    """\W(destinationServiceName|requestClientApplication)=({app}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"timestamp"{1,20}:"{1,20}({time}[^",]{1,2000})"""",
    """\Wsuser=(anonymous|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"categories"{1,20}:\["{1,20}({category}[^",]{1,2000})""",
    """"sourceIp"{1,20}:"{1,20}({src_ip}[^"]{1,2000})"""",
    """"sourcePort"{1,20}:"{1,20}({src_port}\d{1,100})"""",
    """"destinationIp"{1,20}:"{1,20}({dest_ip}[^",]{1,2000})"""",
    """"destinationPort"{1,20}:"{1,20}({dest_port}\d{1,100})""",
    """"identity"{1,20}:"{1,20}({dest_host}[^"]{1,2000})"""",
  ]
}
```