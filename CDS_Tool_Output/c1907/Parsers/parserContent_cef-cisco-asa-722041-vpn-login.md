#### Parser Content
```Java
{
Name = cef-cisco-asa-722041-vpn-login
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ """|CISCO|ASA|""", """|722041|""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """\srt=({time}\d*)""",
    """\|({event_code}722041)""",
    """\sUser\s+<(({domain}[^\\]+)\\)?(?:({user_fullname}(\w+\s+)+\w+)|({user_email}[^@\s>]+@[^@\s>]+?)|({user}[^>@\s]+))>""",
    """\sIP\s+<({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})>""",
    """\sduser=<?(?:({domain}[^\s]+?)\\+)?(?:({user_fullname}(\w+\s+)+\w+)|({user_email}[^@\s>]+@[^@\s>]+?)|({user}[^>@\s]+))>?\s+([\w.]+=|$)""",
    """\sad\.Username=<?(?:({domain}[^\s]+?)\\+)?(?:({user_fullname}(\w+\s+)+\w+)|({user_email}[^@\s>]+@[^@\s>]+?)|({user}[^>@\s]+))>?\s+([\w.]+=|$)""",
    """\sdhost=<?({dest_host}.+?)>?\s+([\w.]+=|$)""",
    """\sdvchost=({host}[^\s]+)""",
  ]
}
```