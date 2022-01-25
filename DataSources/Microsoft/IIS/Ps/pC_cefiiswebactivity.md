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
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdeviceSeverity=({result_code}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sshost=({src_host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\ssuser=(({user_email}[^=@]{1,2000}@[^=@]{1,2000}?)|(({domain}[^=\\\/]{1,2000})[\\\/]{1,2000})?({user}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdpt=({dest_port}\d{1,100})""",
    """\srequest=({uri_path}[^=\?]{1,2000}?)({uri_query}\?.*?)?(\s{1,100}\w+=|\s{0,100}$)""",
    """\srequestMethod=({method}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\srequestClientApplication=({user_agent}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\srequestClientApplication=Mozilla\/[^=]{1,2000}?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]{1,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\scs1=({referrer}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]


}
```