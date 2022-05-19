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
    """({time}\d{1,100})\.\d{1,100}\s{1,100}({host}[\w.\-]{1,2000})\s{1,100}events\s""",
    """\scs6=\d{1,100}\-\d{1,100}\-\d{1,100}T\d\d:\d\d:\d\d\.\d{1,100}Z\s{1,100}({host}[a-fA-F\d.:]{1,2000})""",
    """\sclient_ip\\*='({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sclient_mac\\*='({src_mac}[a-fA-F\d.:]{1,2000})""",
    """\stype\\*=(|({activity}.+?))(\s{1,100}\w+\\*=|\s{0,100}$)""",
    """\said\\*='({aid}[^']{1,2000})""",
    """\schannel\\*='({channel}[^']{1,2000})""",
    """\sduration\\*='({duration}[^']{1,2000})""",
    """\sip_src\\*='({src_ip}[^']{1,2000})""",
    """\sdhcp_ip\\*='({dhcp_ip}[^']{1,2000})""",
    """\sidentity\\*='(({user_email}[^@'\s]{1,2000}@({email_domain}[^\s'.]{1,2000}\.[^\s']{1,2000}))|((({domain}[^'\s\\\/]{1,2000})[\\\/])?({user}[^']{1,2000})))'"""
  ]


}
```