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
      """(Info|CISCOIPORTWSA\-\d{1,100}):\s{1,100}({time}\d{1,100})\.\d{1,100}\s{1,100}\d{1,100}\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}({proxy_action}\w+)\/({result_code}\d{1,100})\s\d{1,100}\s({method}[^\s]+)\s({full_url}[^\s]+)""",
      """(Info|CISCOIPORTWSA\-\d{1,100}):\s{1,100}([^\s]+\s){6}(?:({protocol}\w+):\/{2}({web_domain}[^:\/]+)(:\d{1,100})?({uri_path}\/[^?\s]+)?({uri_query}\?[^\s]+)?)""",
      """(Info|CISCOIPORTWSA\-\d{1,100}):\s{1,100}([^\s]+\s){6}(.*?)({top_domain}[^.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\/|:|\s)).+?)(\/|:|\s)""",
      """(Info|CISCOIPORTWSA\-\d{1,100}):\s{1,100}([^\s]+\s){7}"\w+\\({user}[^@"]+)(@({domain}[^"]+))?"""",
      """(Info|CISCOIPORTWSA\-\d{1,100}):\s{1,100}([^\s]+\s){7}("[^"]+"|\-)\s([^\s]+\s)(?:-|({mime}[^\s]+))\s(?:-|({action}[^\-\s]+))""",
      """\ss-ip=\s{1,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ss-port=\s{1,100}({dest_port}\d{1,100})""",
      """\swebcat-code=\s{1,100}"({category}[^"]+)"""",
      """\scs-bytes=\s{1,100}({bytes_out}\d{1,100})""",
      """\ssc-bytes=\s{1,100}({bytes_in}\d{1,100})""",
      """cs-user-agent=\s{1,100}"Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
      """\scs-user-agent=\s{1,100}"(?:-|({user_agent}[^"]+))"""",
      """\scs-user-agent="(?:-|({browser}[\w\-]+))[^"]*"""",
      """\scs-user-agent="(?:-|({browser}[\w\-]+)\/[\d\._]+)[^"]*"""",
      """\scs-user-agent="(?:-|({browser}.+?)\s{0,100}(for|\(|\d|\/).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))[^"]*"""",
      """Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
      """Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d{1,100}\s{1,100}({browser}\w+)"""
    ]
  }
```