#### Parser Content
```Java
{
Name = cef-catonetworks-network-alert
  Vendor = CatoNetworks
  Product = Cato Cloud
  Lms = ArcSight
  DataType = "network-alert"
  TimeFormat = "EEE MMM dd HH:mm:ss Z yyyy"
  Conditions = [ """CEF:""", """|CatoNetworks|""", """|Security|IPS|""", """internalType=SECURITY""", """ act=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """CEF:([^\|]{0,2000}\|){6}({alert_severity}[^\|]{1,2000})""",
    """\Wrt=({time}\w+\s{1,100}\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}\w+\s{1,100}\d\d\d\d)""",
    """\Wsuser=({user}[^\s]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wmsg=({alert_name}.+?)\s{1,100}(\w+=|$)""",
    """\WinternalType=({alert_type}.+?)\s{1,100}(\w+=|$)""",
    """\WflexString2=({alert_type}.+?)\s{1,100}(\w+=|$)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wclient_port=({src_port}\d{1,100})""",
    """\Wdhost=({dest_host}.+?)\s{1,100}(\w+=|$)""",
    """\Wshost=({user_fullname}.+?)\s{1,100}(\w+=|$)""",
    """\Wurl=({malware_url}.+?)\s{1,100}(\w+=|$)""",
  ]
}
```