#### Parser Content
```Java
{
Name = cef-meraki-network-alert
  Vendor = Cisco
  Product = Cisco Meraki MX appliances
  Lms = ArcSight
  DataType = "network-alert"
  TimeFormat = "epoch"
  Conditions = [ """destinationServiceName =Cisco Meraki""", """security_events""", """"classification":""", """"signature":""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\WdestinationServiceName =(|({event_subtype}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdproc=(|({process}[^=]?))(\s{1,100}\w+=|\s{0,100}$)""",
    """destIp":"({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({dest_port}\d{1,100})""",
    """"ts":({time}\d{1,100})""",
    """"srcIp":"({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({src_port}\d{1,100})""",
    """"protocol":"({protocol}[^"]{1,2000})""",
    """"blocked":({outcome}\w{1,2000}),""",
    """"message":"({alert_name}[^"]{1,200})""",
    """"deviceMac":"({src_mac_address}[^"]{1,2000})""",
    """"priority":"({alert_severity}\d{1,2000})""",
    """destinationServiceName =({app}Cisco Meraki)""",
  ]


}
```