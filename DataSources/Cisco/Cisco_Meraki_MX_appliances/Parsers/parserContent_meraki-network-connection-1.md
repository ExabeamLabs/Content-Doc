#### Parser Content
```Java
{
Name = meraki-network-connection-1
  Vendor = Cisco
  Product = Cisco Meraki MX appliances
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """ events """, """ type""", """ aid""" ]
  Fields = [
    """({time}\d{1,100})\.\d{1,100}\s{1,100}({host}[\w.\-]+)\s{1,100}events\s""",
    """\scs6=\d{1,100}\-\d{1,100}\-\d{1,100}T\d\d:\d\d:\d\d\.\d{1,100}Z\s{1,100}({host}[a-fA-F\d.:]+)""",
    """\sclient_ip\\*='({src_ip}[a-fA-F\d.:]+)""",
    """\sclient_mac\\*='({src_mac}[a-fA-F\d.:]+)""",
    """\stype\\*=(|({activity}.+?))(\s{1,100}\w+\\*=|\s{0,100}$)""",
    """\said\\*='({aid}[^']+)""",
    """\schannel\\*='({channel}[^']+)""",
    """\sduration\\*='({duration}[^']+)""",
    """\sip_src\\*='({src_ip}[^']+)""",
    """\sdhcp_ip\\*='({dhcp_ip}[^']+)""",
  ]
  DupFields = [ "aid->user" ]
}
```