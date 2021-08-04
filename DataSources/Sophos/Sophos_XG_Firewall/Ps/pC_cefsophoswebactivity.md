#### Parser Content
```Java
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
    """\Wrt=({time}\d{1,100})""",
    """\Wdate=({time}\d{1,100}-\d{1,100}-\d{1,100}\s{0,100}time=\d{1,100}:\d{1,100}:\d{1,100})""",
    """\Wdevice_name="({host}[\w\-.]{1,2000})""",
    """\Wdvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wlog_subtype="({action}[^"]{1,2000})"""",
    """\Wuser_name="({user}[^\s@"]{1,2000})"""",
    """\Wuser_name="({user_email}[^\s@"]{1,2000}@[^\s@"]{1,2000})"""",
    """\Wcategory="(None|({category}[^"]{1,2000}))"""",
    """\Wurl="(|({full_url}(({protocol}[^:\\\/\s"]{1,2000}):[\\\/]{1,2000})?({web_domain}[^\\\/\s:"]{1,2000})(:\d{1,100})?({uri_path}\/[^\s\?"]{0,2000})?({uri_query}\?[^"\s]{0,2000})?))"""",
    """\Wsrc(_ip)?=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst(_ip)?=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\W(spt|src_port)=({src_port}\d{1,100})""",
    """\W(dpt|dst_port)=({dest_port}\d{1,100})""",
    """\Wdhost=({dest_host}[\w\-.]{1,2000})""",
    """\Wprotocol="({protocol}[^"]{1,2000})"""",
    """\W(in|recv_bytes)=({bytes_in}\d{1,100})""",
    """\W(out|sent_bytes)=({bytes_out}\d{1,100})""",
    """\Wuser_agent\\?="({user_agent}[^"]{1,2000})"""",
    """\Wuser_agent\\?="[^"]{0,2000}?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """\Wuser_agent\\?="[^"]{0,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\Wstatus_code\\?="({result_code}\d{1,100})""",
    """\W(dntdom|domain)=({web_domain}[^\s]{1,2000})""",
    """\W(dntdom|domain)=[^\s=]{0,2000}?({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|site|aws))+(\s|\/|$))[^\s\/]{1,2000})""",
    """\W(fname|file_name)="?(|({file_name}[^"]{1,2000}?))"?\s{1,100}(\w+=|$)""",
    """\Wcontenttype="({mime}[^"]{1,2000})""", 
  ]
}
```