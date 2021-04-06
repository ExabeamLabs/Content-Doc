#### Parser Content
```Java
{
Name = n-mwg-proxy
    Vendor = McAfee
    Product = McAfee Web Gateway
    Lms = NitroCefSyslog
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
    Conditions = [ """McAfeeWG|""","""mwg:""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]+)""",
      """\|time_stamp=\[({time}[^\]]+)""",
      """\|server_ip=({dest_ip}[^|]+)""",
      """\|auth_user=(?:|({user}[^|]+))\|""",
      """\|src_ip=(?:|({src_ip}[^|]+))\|""",
      """\|host=(?:|({dest_host}[^|]+))\|""",
      """\|status_code=(?:|({result_code}[^|]+))\|""",
      """\|user_agent=(?:|({user_agent}[^|]+))\|""",
      """\|user_agent=({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)?[^|]+?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
      """Mozilla\/[^|]+?\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^|]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
      """Mozilla\/[^|]+?\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^|]+?Gecko\/\d+\s+({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
      """\|method=(?:|({method}[^|]+))\|""",
      """\|url=(-|({full_url}[^|]+?))\|""",
      """\|url=(\w+:\/+)?([^\/.]+\.)*({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s\/]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))(\||\/))[^|\/]+)""",
      """\|url=(?:|(\w+:\/+)?({web_domain}(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^\/:|]+))[^|]*)\|""",
      """\|url=(?:|(\w+:\/+)?[^|\/:]+(:\d+)?({uri_path}\/[^?|]+)[^|]*)\|""",
      """\|url=(?:|(\w+:\/+)?[^|\/:]+(:\d+)?[^|?]+({uri_query}\?[^|]+))\|""",
      """\|categories=(?:|({category}[^,|]+))(,|\|)""",
      """\|bytes_to_client=(?:|({bytes_in}\d+))\|""",
      """\|bytes_from_client=(?:|({bytes_out}\d+))\|""",
      """\|block_reason=(?:|({failure_reason}[^|]+))\|""",
      """\|media_type=(?:|({mime}[^|]+?))\s*(\||$)"""
    ]
  }
```