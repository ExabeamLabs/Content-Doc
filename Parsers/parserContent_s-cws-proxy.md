#### Parser Content
```Java
{
Name = s-cws-proxy
    Vendor = Cisco
    Product = Cisco Cloud Web Security
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch_sec"
    Conditions = [ """ wbrs-score=""",""" webcat-code="""]
    Fields = [
      """exabeam_host=({host}[\w\-.]+)""",
      """(Info|CISCOIPORTWSA\-\d+):\s+({time}\d+)\.\d+\s+\d+\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+({proxy_action}\w+)\/({result_code}\d+)\s\d+\s({method}[^\s]+)\s({full_url}[^\s]+)""",
      """(Info|CISCOIPORTWSA\-\d+):\s+([^\s]+\s){6}(?:({protocol}\w+):\/{2}({web_domain}[^:\/]+)(:\d+)?({uri_path}\/[^?\s]+)?({uri_query}\?[^\s]+)?)""",
      """(Info|CISCOIPORTWSA\-\d+):\s+([^\s]+\s){6}(.*?)({top_domain}[^.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\/|:|\s)).+?)(\/|:|\s)""",
      """(Info|CISCOIPORTWSA\-\d+):\s+([^\s]+\s){7}"\w+\\({user}[^@"]+)(@({domain}[^"]+))?"""",
      """(Info|CISCOIPORTWSA\-\d+):\s+([^\s]+\s){7}("[^"]+"|\-)\s([^\s]+\s)(?:-|({mime}[^\s]+))\s(?:-|({action}[^\-\s]+))""",
      """\ss-ip=\s+({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ss-port=\s+({dest_port}\d+)""",
      """\swebcat-code=\s+"({category}[^"]+)"""",
      """\scs-bytes=\s+({bytes_out}\d+)""",
      """\ssc-bytes=\s+({bytes_in}\d+)""",
      """cs-user-agent=\s+"Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
      """\scs-user-agent=\s+"(?:-|({user_agent}[^"]+))"""",
      """\scs-user-agent="(?:-|({browser}[\w\-]+))[^"]*"""",
      """\scs-user-agent="(?:-|({browser}[\w\-]+)\/[\d\._]+)[^"]*"""",
      """\scs-user-agent="(?:-|({browser}.+?)\s*(for|\(|\d|\/).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))[^"]*"""",
      """Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
      """Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+)"""
    ]
  }
```