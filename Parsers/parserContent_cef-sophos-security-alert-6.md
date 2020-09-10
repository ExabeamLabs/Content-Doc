#### Parser Content
```Java
{
Name = cef-sophos-security-alert-6
  Conditions = [ """|sophos|sophos central|""", """|Event::Endpoint::HmpaBehaviourPrevented|""" ]
}

{
  Name = cef-sophos-web-activity
  Vendor = Sophos
  Product = Sophos XG Firewall
  Lms = ArcSight
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """log_type="Content Filtering"""", """ url="""", """status_code""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdate=({time}\d+-\d+-\d+\s*time=\d+:\d+:\d+)""",
    """\Wdevice_name="({host}[\w\-.]+)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wlog_subtype="({action}[^"]+)"""",
    """\Wuser_name="({user}[^\s@"]+)"""",
    """\Wuser_name="({user_email}[^\s@"]+@[^\s@"]+)"""",
    """\Wcategory="(None|({category}[^"]+))"""",
    """\Wurl="(|({full_url}(({protocol}[^:\\\/\s"]+):[\\\/]+)?({web_domain}[^\\\/\s:"]+)(:\d+)?({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?))"""",
    """\Wsrc(_ip)?=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wdst(_ip)?=({dest_ip}[A-Fa-f:\d.]+)""",
    """\W(spt|src_port)=({src_port}\d+)""",
    """\W(dpt|dst_port)=({dest_port}\d+)""",
    """\Wdhost=({dest_host}[\w\-.]+)""",
    """\Wprotocol="({protocol}[^"]+)"""",
    """\W(in|recv_bytes)=({bytes_in}\d+)""",
    """\W(out|sent_bytes)=({bytes_out}\d+)""",
    """\Wuser_agent\\?="({user_agent}[^"]+)"""",
    """\Wuser_agent\\?="[^"]*?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """\Wuser_agent\\?="[^"]*?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\Wstatus_code\\?="({result_code}\d+)""",
    """\W(dntdom|domain)=({web_domain}[^\s]+)""",
    """\W(dntdom|domain)=[^\s=]*?({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|site|aws))+(\s|\/|$))[^\s\/]+)""",
    """\W(fname|file_name)="?(|({file_name}[^"]+?))"?\s+(\w+=|$)""",
  ]
}
```