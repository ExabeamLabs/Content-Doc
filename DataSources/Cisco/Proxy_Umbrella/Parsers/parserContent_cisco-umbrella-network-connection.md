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
    """\W(destinationServiceName|requestClientApplication)=({app}.+?)(\s+\w+=|\s*$)""",
    """"timestamp"+:"+({time}[^",]+)"""",
    """\Wsuser=(anonymous|({user}.+?))(\s+\w+=|\s*$)""",
    """"categories"+:\["+({category}[^",]+)""",
    """"sourceIp"+:"+({src_ip}[^"]+)"""",
    """"sourcePort"+:"+({src_port}\d+)"""",
    """"destinationIp"+:"+({dest_ip}[^",]+)"""",
    """"destinationPort"+:"+({dest_port}\d+)""",
    """"identity"+:"+({dest_host}[^"]+)"""",
  ]
}
```