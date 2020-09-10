#### Parser Content
```Java
{
Name = cws-proxy
    Vendor = Cisco
    Product = Cisco Cloud Web Security
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """|CISCO|Cloud Web Security|""","""requestMethod="""]
    Fields = [
      """\srt=({time}\d+)""",
      """\sagt=({host}[^\s]+)""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\srequest=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({dest_port}\d+))?""",
      """\ssrc=(?:0\.0\.0\.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
      """\sshost=(?:|({src_host}.+?))\s\w+=""",
      """\sduser=([^\s\\]+\\+)?(?:|UNDISCLOSED|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({user}.+?))\s\w+=""",
      """\sact=(?:|({action}.+?))\s\w+=""",
      """\srequestMethod=(?:|({method}.+?))\s\w+=""",
      """\sout=({bytes_out}\d+)\s\w+=""",
      """\sin=({bytes_in}\d+)\s\w+=""",
      """\|CISCO\|Cloud Web Security\|[^|]*\|(?:0|({result_code}\d+))\|""",
      """\srequest=(?:-|({full_url}\S+))""",
      """\srequest=(?:-|(\w+:\/+)?({web_domain}[^:\/\s]+))""",
      """\srequest=(?:-|(({protocol}[^:]+))):\/""",
      """\srequest=(?:-|((\w+:\/+)?[^\/]+({uri_path}\/.*?)))(\?[^\s]*)?\srequestMethod=""",
      """\srequest=(?:-|((\w+:\/+)?[^?]*({uri_query}\?.*?)))\srequestMethod=""",
      """\srequestClientApplication=(?:-|({user_agent}.+?))\s\w+=""",
      """\scs2=(?:unclassified|({category}.+?))\s\w+=""",
      """\sfileType=(?:-|({mime}.+?))\s\w+=""",
      """\srequest=(.*?)({top_domain}[^.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\/|:|\s)).+?)(\/|:|\s\w+=)"""
      """\srequestClientApplication=(?:-|({browser}[\w\-]+))""",
      """\srequestClientApplication=(?:-|({browser}[\w\-]+)\/[\d\._]+)""",
      """\srequestClientApplication=(?:-|({browser}.+?)\s*(for|\(|\d|\/).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
      """Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
      """Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+)"""
    ]
  }
```