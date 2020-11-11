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
    """({time}\d+)\.\d+\s+({host}[\w.\-]+)\s+events\s""",
    """\scs6=\d+\-\d+\-\d+T\d\d:\d\d:\d\d\.\d+Z\s+({host}[a-fA-F\d.:]+)""",
    """\sclient_ip\\*='({src_ip}[a-fA-F\d.:]+)""",
    """\sclient_mac\\*='({src_mac}[a-fA-F\d.:]+)""",
    """\stype\\*=(|({activity}.+?))(\s+\w+\\*=|\s*$)""",
    """\said\\*='({aid}[^']+)""",
    """\schannel\\*='({channel}[^']+)""",
    """\sduration\\*='({duration}[^']+)""",
    """\sip_src\\*='({src_ip}[^']+)""",
    """\sdhcp_ip\\*='({dhcp_ip}[^']+)""",
  ]
  DupFields = [ "aid->user" ]
}
```