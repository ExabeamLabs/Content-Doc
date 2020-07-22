#### Parser Content
```Java
{
Name = forcepoint-proxy
    Vendor = Forcepoint
    Product = Forcepoint Web Security
    Lms = QRadar
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """LEEF:""","""|Forcepoint|Security|""","""|transaction:""","""srcBytes=""" ]
    Fields = [
      """exabeam_endTime=({time}\d+)""",
      """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ssrcPort=({src_port}\d+)""",
      """\sdstPort=({dest_port}\d+)""",
      """\susrName=(?:\w+:\/+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+({user_ou}[^\/]+)\/({user_fullname}.+?)\s+([\w\-]+=|$)""",
      """\sloginID=(-|(({domain}[^=]+?)[\\\/]+)?({user}.+?))(\s+\w+=|\s*$)""",
      """\|transaction:({action}[^\|]+)""",
      """\smethod=(?:-|({method}[^\s]+))""",
      """\ssrcBytes=({bytes_in}\d+)""",
      """\sdstBytes=({bytes_out}\d+)""",
      """\surl=(?:-|({full_url}[^\s"]+))""",
      """\surl=(?:-|({protocol}[^:]+))""",
      """\surl=(?:[^:]+:\/+)({web_domain}[^\/:\s"]+)""",
      """\surl=(?:-|\w+:\/+[^\/]+)({uri_path}\/[^?\s"]+)""",
      """\surl=(?:-|(?=(?)(?:[^?]+({uri_query}\?[^\s"]+))))""",
      """\suserAgent=(?:-|({user_agent}.+?))\s+url=""",
      """exabeam_qidName=.+?\s\-\s({category}.+?)\s+exabeam_""",
      """\scontentType=(?:-|({mime}.+?))\s+reason=""",
      """\sproxyStatus-code=({result_code}\d+)""",
      """\surl=(.*?)({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\s|\/|$))[^\s\/]+)""",
      """\suserAgent=(?:-|({browser}[\w\-]+))""",
      """\suserAgent=(?:-|({browser}[\w\-]+)\/[\d\._]+)""",
      """\suserAgent=(?:-|({browser}[^\/]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
      """\suserAgent=(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
      """\suserAgent=(?:-|Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+))""",
    ]
  }
```