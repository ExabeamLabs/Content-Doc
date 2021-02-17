#### Parser Content
```Java
{
Name = netscaler-cef-vpn-end
  Vendor = Citrix
  Product = Citrix Netscaler
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [  """|Citrix|NetScaler|""", """LOGOUT|""" ]
  Fields = [ """exabeam_EventTime=({eventtime}\d+)""",
    """\srt=({time}\d+)""",
    """\s(s|d)user=({user}.+?)\s+\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({src_host}[^\s]+)""",
    """\sdhost=({dest_host}[^\s]+)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)""",
    """SessionId:\s+({session_id}\d+)""",
    """cn1=({session_id}\d+)"""
  ]
}
```