#### Parser Content
```Java
{
Name = fortinet-ssl-failed-vpn-login
  DataType = "failed-vpn-login"
  TimeFormat = "yyyy-MM-dd 'time='HH:mm:ssZ"
  Conditions = [ """action="ssl-login-fail"""", """subtype="vpn"""" ]
  Fields = ${FortinetParserTemplates.fortinet-ssl-vpn.Fields} [
    """reason="({failure_reason}[^"]+)""",
  ]
}

{
  Name = fortinet-web-activity
  Vendor = Fortinet
  Product = Fortinet UTM
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd' time='HH:mm:ss"
  Conditions = [ """subtype=""","""webfilter""", """devname=""", """date=""", """url=""" ]
  Fields = [
    """\Wdate=({time}\d\d\d\d-\d\d-\d\d time\=\d\d:\d\d:\d\d([+-]\d\d:\d\d)?)""",
    """\Wdevname="*({host}[^\s"]+)"*(\s|")""",
    """\Waction="*({action}[^\s"]+)"*(\s|")""",
    """\Wstatus="*({action}[^"]+)"""",
    """\Wurl="*(?:-|\w+:\/+[^\/]+)?({uri_path}\/[^?\s"]*)""",
    """\Wurl="*(?:[^?]+?(|({uri_query}\?[^\s"]+)))["\s]*(\w+=|$)""",
    """\Wcatdesc="*({category}[^"]+?)["\s]*(\w+=|$|,)""",
    """\Wuser="*({user}[^"\s]+)""",
    """\Wsrcip=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdstip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Whostname="*({web_domain}[^"\s]+)""",
    """\Wservice="*({protocol}[^\s"]+)"*(\s|")""",
    """\Wlevel="*({risk_level}[^\s"]+)"*(\s|")""",
    """\Wdstport=({dest_port}\d+)(\s|")""",
    """\Wsentbyte=({bytes_out}\d+)(\s|")""",
    """\Wrcvdbyte=({bytes_in}\d+)(\s|")""",
    """\Wdevid="*({host_id}[^"\s]+)"*(\s|")""",
    """\Wreferralurl="*({referrer}[^"\s]+)""",
    """\Wgroup="*({user_group}.+?)["\s]*(\w+=|$)""",
    """\Wmsg="*({additional_info}.+?)["\s]*(\w+=|$)""",
    """\Waction="*blocked"*.+?\Wmsg="*({reason}.+?)["\s]*(\w+=|$)""",
    """\Wmsg="*({reason}.+?)["\s]*(\w+=|$).+?\Waction="*blocked"*""",
    """\Whostname="*(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})([^"\s]*\.)?({top_domain}[^\s\/."]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|by|mx))+)""",
    """\Wurl="({full_url}[^"]+)"""",
  ]
}
```