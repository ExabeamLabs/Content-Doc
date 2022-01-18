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
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """\|time_stamp=\[({time}[^\]]{1,2000})""",
      """\|server_ip=({dest_ip}[^|]{1,2000})""",
      """\|auth_user=(?:|({user}[^|]{1,2000}))\|""",
      """\|src_ip=(?:|({src_ip}[^|]{1,2000}))\|""",
      """\|host=(?:|({dest_host}[^|]{1,2000}))\|""",
      """\|status_code=(?:|({result_code}[^|]{1,2000}))\|""",
      """\|user_agent=(?:|({user_agent}[^|]{1,2000}))\|""",
      """\|user_agent=({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)?[^|]{1,2000}?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
      """Mozilla\/[^|]{1,2000}?\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^|]{1,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
      """Mozilla\/[^|]{1,2000}?\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^|]{1,2000}?Gecko\/\d{1,100}\s{1,100}({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
      """\|method=(?:|({method}[^|]{1,2000}))\|""",
      """\|url=(-|({full_url}[^|]{1,2000}?))\|""",
      """\|url=(\w+:\/+)?([^\/.]{1,2000}\.)*({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))(\||\/))[^|\/]{1,2000})""",
      """\|url=(?:|(\w+:\/+)?({web_domain}(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^\/:|]{1,2000}))[^|]{0,2000})\|""",
      """\|url=(?:|(\w+:\/+)?[^|\/:]{1,2000}(:\d{1,100})?({uri_path}\/[^?|]{1,2000})[^|]{0,2000})\|""",
      """\|url=(?:|(\w+:\/+)?[^|\/:]{1,2000}(:\d{1,100})?[^|?]{1,2000}({uri_query}\?[^|]{1,2000}))\|""",
      """\|categories=(?:|({category}[^,|]{1,2000}))(,|\|)""",
      """\|bytes_to_client=(?:|({bytes_in}\d{1,100}))\|""",
      """\|bytes_from_client=(?:|({bytes_out}\d{1,100}))\|""",
      """\|block_reason=(?:|({failure_reason}[^|]{1,2000}))\|""",
      """\|media_type=(?:|({mime}[^|]{1,2000}?))\s{0,100}(\||$)"""
    ]
  

}
```