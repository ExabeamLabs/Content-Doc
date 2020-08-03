#### Parser Content
```Java
{
Name = s-sharepoint-proxy
  Vendor = Microsoft
  Product = Sharepoint
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """<custom condition>""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) ({src_ip}[a-fA-F\d.:]+) GET""",
    """GET \S+ \S+ ({dest_port}\d+) (-|[^|]+\|(({domain}[^\\]+)\\)?({user}[^\\\s]+)) ({dest_ip}[a-fA-F\d.:]+)""",
    """GET (\S+ ){5}\S*({os}iOS|Android|BlackBerry|Windows Phone|BeOS|Windows|Linux|Macintosh|Darwin)""",
    """GET (\S+ ){5}\S*({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """GET (\S+ ){6}(-|({full_url}\S+))""",
    """GET (\S+ ){6}\w+:\/+({web_domain}[^/]+)""",
    """GET (\S+ ){6}\w+:\/+[^/]*?({top_domain}[^./]+(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)\/""",
    """GET (\S+ ){7}({result_code}\d+)""",
  ]
}

  {
  Name = cef-iis-web-activity
  Vendor = Microsoft
  Product = IIS
  Lms = ArcSight
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Microsoft|Internet Information Server|""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sdvc=({host}.+?)(\s+\w+=|\s*$)""",
    """\sdvchost=({host}.+?)(\s+\w+=|\s*$)""",
    """\sdeviceSeverity=({result_code}.+?)(\s+\w+=|\s*$)""",
    """\sshost=({src_host}.+?)(\s+\w+=|\s*$)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """\ssuser=(({user_email}[^=@]+@[^=@]+?)|(({domain}[^=\\\/]+)[\\\/]+)?({user}[^=]+?))(\s+\w+=|\s*$)""",
    """\sdpt=({dest_port}\d+)""",
    """\srequest=({uri_path}[^=\?]+?)({uri_query}\?.*?)?(\s+\w+=|\s*$)""",
    """\srequestMethod=({method}.+?)(\s+\w+=|\s*$)""",
    """\srequestClientApplication=({user_agent}.+?)(\s+\w+=|\s*$)""",
    """\srequestClientApplication=Mozilla\/[^=]+?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\scs1=({referrer}.+?)(\s+\w+=|\s*$)""",
  ]
}
```