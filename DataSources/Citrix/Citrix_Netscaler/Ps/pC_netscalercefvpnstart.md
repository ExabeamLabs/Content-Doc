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
    """\sClient_ip\s{1,100}({src_ip}[\d\.a-fA-F:]{1,2000})\s""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\s(s|d)user=({user}.+?)\s{1,100}\w+=""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({src_host}[^\s]{1,2000})""",
    """\sdhost=({dest_host}[^\s]{1,2000})""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """SessionId:\s{1,100}({session_id}\d{1,100})""",
    """cn1=({session_id}\d{1,100})""",
    """Browser_type "{1,20}({user_agent}[^"]{1,2000})""",
    """Browser_type\s{0,100}({user_agent}[^\-]{1,2000}?)\s{0,100}\-""",
    """requestClientApplication=({user_agent}.+?)\s{1,100}\w+=""",
    """SSLVPN_client_type\s{0,100}({vpn_client_type}[^\-]{1,2000}?)\s\-""", 
    """Group\(s\) "{1,20}(N\/A|({realm}[^"]{1,2000}))""",
    """ Nat_ip ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
  DupFields = ["user->account"]


}
```