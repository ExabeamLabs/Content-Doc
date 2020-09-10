#### Parser Content
```Java
{
Name = cef-catonetworks-network-alert
  Vendor = CatoNetworks
  Product = CatoNetworks
  Lms = ArcSight
  DataType = "network-alert"
  TimeFormat = "EEE MMM dd HH:mm:ss Z yyyy"
  Conditions = [ """CEF:""", """|CatoNetworks|""", """|Security|IPS|""", """internalType=SECURITY""", """ act=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """CEF:([^\|]*\|){6}({alert_severity}[^\|]+)""",
    """\Wrt=({time}\w+\s+\w+\s+\d+\s+\d\d:\d\d:\d\d\s+\w+\s+\d\d\d\d)""",
    """\Wsuser=({user}[^\s]+)\s+(\w+=|$)""",
    """\Wmsg=({alert_name}.+?)\s+(\w+=|$)""",
    """\WinternalType=({alert_type}.+?)\s+(\w+=|$)""",
    """\WflexString2=({alert_type}.+?)\s+(\w+=|$)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wdpt=({dest_port}\d+)""",
    """\Wclient_port=({src_port}\d+)""",
    """\Wdhost=({dest_host}.+?)\s+(\w+=|$)""",
    """\Wshost=({user_fullname}.+?)\s+(\w+=|$)""",
    """\Wurl=({malware_url}.+?)\s+(\w+=|$)""",
  ]
}
```