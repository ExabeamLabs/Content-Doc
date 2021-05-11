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
  Fields = [ """exabeam_EventTime=({eventtime}\d{1,100})""",
    """\srt=({time}\d{1,100})""",
    """\sClient_ip\s{1,100}({src_ip}[\d\.a-fA-F:]+)\s""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\s(s|d)user=({user}.+?)\s{1,100}\w+=""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({src_host}[^\s]+)""",
    """\sdhost=({dest_host}[^\s]+)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)""",
    """SessionId:\s{1,100}({session_id}\d{1,100})""",
    """cn1=({session_id}\d{1,100})""",
    """Browser_type "{1,20}({user_agent}[^"]+)""",
    """Browser_type\s{0,100}({user_agent}[^\-]+?)\s{0,100}\-""",
    """Browser_type (\")+(?:-|({browser}[^\/]+).+({os}iOS|Android|BlackBerry|iPhone OS|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """Browser_type (\")+(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """requestClientApplication=({user_agent}.+?)\s{1,100}\w+=""",
    """SSLVPN_client_type\s{0,100}({vpn_client_type}[^\-]+?)\s\-""", 
    """Group\(s\) "{1,20}(N\/A|({realm}[^"]+))""",
    """ Nat_ip ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
  DupFields = ["user->account"]
}
```