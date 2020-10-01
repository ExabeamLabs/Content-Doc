#### Parser Content
```Java
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