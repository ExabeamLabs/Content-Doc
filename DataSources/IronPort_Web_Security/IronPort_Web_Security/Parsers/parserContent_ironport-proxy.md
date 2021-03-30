#### Parser Content
```Java
{
Name = ironport-proxy
    Vendor = IronPort Web Security
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """|CISCO|IronPort Web Security Appliance|""","""categorySignificance="""]
    Fields = [
      """\srt=({time}\d+)""",
      """exabeam_host=({host}[^\s]+)""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]+)""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\srequest=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({dest_port}\d+))?""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sduser=(({domain}[^\s\\]+)\\+)?({user}.+?)\s\w+=""",
      """\sact=(?:NONE|({proxy_action}.+?))\s\w+=""",
      """\scategoryOutcome=\/({action}.+?)\s\w+=""",
      """\srequestMethod=({method}.+?)\s\w+=""",
      """\sout=({bytes_out}\d+)\s\w+=""",
      """\sin=({bytes_in}.+?)\s\w+=""",
      """\|CISCO\|IronPort Web Security Appliance\|[^|]*\|({result_code}.+?)\|""",
      """\sdhost=(?:-|({web_domain}.+?))\s\w+=""",
      """\smsg=(?:-|(\w+\s+({protocol}[^:]+))):\/\/""",
      """\srequest=(-|({full_url}\S+))""",
      """\srequest=(?:-|(\w+:\/+[^\/]+\/({uri_path}.+?)))(\?.+?)?\srequestMethod=""",
      """\smsg=(?:-|(\w+\s+\w+:\/+[^?]+({uri_query}\?.+?)))\sin=""",
      """\scs2=(?:-|({user_agent}.+?))\s\w+=""",
      """\scs3=(?:ns|({score}.+?))\s\w+=""",
      """\scs4=.+?(KHTML,)?([^,]*,){19}(?:(-|nc|Unknown)|({category}[^,]+))""",
      """\scs4=.+?(KHTML,)?([^,]*,){22}"*(?:(-|Unknown|nc)|({category}[^",]+))""",
      """\sfileType=(?:-|({mime}.+?))\s\w+=""",
      """\sdhost=(.*?)({top_domain}[^.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+\s\w+=).+?)\s\w+="""
      """\scs2=(?:-|({browser}[\w\-]+))""",
      """\scs2=(?:-|({browser}[\w\-]+)\/[\d\._]+)""",
      """\scs2=(?:-|({browser}[^\/]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
      """\scs2=(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
      """\scs2=(?:-|Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+))"""
    ]
    DupFields = [ "user->orig_user" ]
  }
```