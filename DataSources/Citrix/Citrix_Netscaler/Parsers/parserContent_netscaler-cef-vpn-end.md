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
  Fields = [ """exabeam_EventTime=({eventtime}\d{1,100})""",
    """\srt=({time}\d{1,100})""",
    """\s(s|d)user=({user}.+?)\s{1,100}\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({src_host}[^\s]{1,2000})""",
    """\sdhost=({dest_host}[^\s]{1,2000})""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """SessionId:\s{1,100}({session_id}\d{1,100})""",
    """cn1=({session_id}\d{1,100})"""
  ]
}
```