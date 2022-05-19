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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\srt=({time}\d{0,100})""",
    """\|({event_code}722041)""",
    """\sUser\s{1,100}<(({domain}[^\\]{1,2000})\\)?(?:({user_fullname}(\w+\s{1,100})+\w+)|({user_email}[^@\s>]{1,2000}@[^@\s>]{1,2000}?)|({user}[^>@\s]{1,2000}))>""",
    """\sIP\s{1,100}<({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})>""",
    """\sduser=<?(?:({domain}[^\s]{1,2000}?)\\+)?(?:({user_fullname}(\w+\s{1,100})+\w+)|({user_email}[^@\s>]{1,2000}@[^@\s>]{1,2000}?)|({user}[^>@\s]{1,2000}))>?\s{1,100}([\w.]{1,2000}=|$)""",
    """\sad\.Username=<?(?:({domain}[^\s]{1,2000}?)\\+)?(?:({user_fullname}(\w+\s{1,100})+\w+)|({user_email}[^@\s>]{1,2000}@[^@\s>]{1,2000}?)|({user}[^>@\s]{1,2000}))>?\s{1,100}([\w.]{1,2000}=|$)""",
    """\sdhost=<?({dest_host}.+?)>?\s{1,100}([\w.]{1,2000}=|$)""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\sc6a3=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}).*?c6a3Label=Destination""", 
  ]
  DupFields = ["user->account"]


}
```