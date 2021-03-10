#### Parser Content
```Java
{
Name = netscaler-cef-vpn-start
  Vendor = Citrix Netscaler
  Product = Citrix Netscaler
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ """|Citrix|NetScaler|""","""LOGIN|""" ]
  Fields = [ """exabeam_EventTime=({eventtime}\d+)""",
    """\srt=({time}\d+)""",
    """\sClient_ip\s+({src_ip}[\d\.a-fA-F:]+)\s""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\s(s|d)user=({user}.+?)\s+\w+=""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({src_host}[^\s]+)""",
    """\sdhost=({dest_host}[^\s]+)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)""",
    """SessionId:\s+({session_id}\d+)""",
    """cn1=({session_id}\d+)""",
    """Browser_type "+({user_agent}[^"]+)""",
    """Browser_type\s*({user_agent}[^\-]+?)\s*\-""",
    """requestClientApplication=({user_agent}.+?)\s+\w+="""
  ]
}
```