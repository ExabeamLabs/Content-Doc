#### Parser Content
```Java
{
Name = netscaler-cef-vpn-start
  Vendor = Citrix
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
    """Browser_type (\")+(?:-|({browser}[^\/]+).+({os}iOS|Android|BlackBerry|iPhone OS|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """Browser_type (\")+(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """requestClientApplication=({user_agent}.+?)\s+\w+=""",
    """SSLVPN_client_type\s*({vpn_client_type}[^\-]+?)\s\-""", 
    """Group\(s\) "+(N\/A|({realm}[^"]+))""",
    """ Nat_ip ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
  DupFields = ["user->account"]
}
```