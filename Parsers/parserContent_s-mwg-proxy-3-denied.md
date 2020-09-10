#### Parser Content
```Java
{
Name = s-mwg-proxy-3-denied
    Vendor = McAfee
    Product = McAfee Web Gateway
    Lms = Splunk
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
    Conditions = [ """mwg: Acces Denied [""" ]
    Fields = [
      """exabeam_host=({host}[^\s]+)""",
      """\s+({host}[^\s]+)\s+mwg:""",
      """({failure_reason}Acces Denied)""",
      """mwg:\s+Acces Denied\s+\[({time}[^\]]+)\]""",
      """mwg:\s+Acces Denied\s+\[.+?\]\s+".*?"\s+"(?:|-|({user}[^"]+))"""",
      """mwg:\s+Acces Denied\s+\[.+?\]\s+(".*?"\s+){2}({src_ip}[^\s]+)""",
      """mwg:\s+Acces Denied\s+\[.+?\]\s+(".*?"\s+){2}[^\s]+\s+({dest_ip}[^\s]+)""",
      """mwg:\s+Acces Denied\s+\[.+?\]\s+("[^"]*?"\s+){2}([^\s]+\s+){2}"(?:"|-"|({web_domain}[^\s"]+)")""",
      """mwg:\s+Acces Denied\s+\[.+?\]\s+("[^"]*?"\s+){2}([^\s]+\s+){2}"(?:|-|.*?({top_domain}(?!(\d+\.){3}\d+)[^\.]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+))"""",
      """mwg:\s+Acces Denied\s+\[.+?\]\s+("[^"]*?"\s+){2}([^\s]+\s+){2}"[^"]*?"\s+({result_code}\d+)""",
      """mwg:\s+Acces Denied\s+\[.+?\]\s+("[^"]*?"\s+){2}([^\s]+\s+){2}"[^"]*?"\s+\d+\s+"[^"]*?"\s+({bytes_out}\d+)""",
      """mwg:\s+Acces Denied\s+\[.+?\]\s+("[^"]*?"\s+){2}([^\s]+\s+){2}"[^"]*?"\s+\d+\s+"[^"]*?"\s+\d+\s+({bytes_in}\d+)""",
      """mwg:\s+Acces Denied\s+\[.+?\]\s+("[^"]*?"\s+){2}([^\s]+\s+){2}"[^"]*?"\s+\d+\s+"[^"]*?"\s+(\d+\s+){2}"({method}[^\s]+)""",
      """mwg:\s+Acces Denied\s+\[.+?\]\s+("[^"]*?"\s+){2}([^\s]+\s+){2}"[^"]*?"\s+\d+\s+"[^"]*?"\s+(\d+\s+){2}"\w+\s+(?:({protocol}\w+):\/+)?""",
      """mwg:\s+Acces Denied\s+\[.+?\]\s+("[^"]*?"\s+){2}([^\s]+\s+){2}"[^"]*?"\s+\d+\s+"[^"]*?"\s+(\d+\s+){2}"\w+\s+(\w+:\/+)?[^\/:]+:({dest_port}\d+)""",
      """mwg:\s+Acces Denied\s+\[.+?\]\s+("[^"]*?"\s+){2}([^\s]+\s+){2}"[^"]*?"\s+\d+\s+"[^"]*?"\s+(\d+\s+){2}"\w+\s+({full_url}\S+)""",
      """mwg:\s+Acces Denied\s+\[.+?\]\s+("[^"]*?"\s+){2}([^\s]+\s+){2}"[^"]*?"\s+\d+\s+"[^"]*?"\s+(\d+\s+){2}"\w+\s+(\w+:\/+)?[^\/:]+(:\d+)?({uri_path}\/.*?)(\?|\s+[^\s]+")""",
      """mwg:\s+Acces Denied\s+\[.+?\]\s+("[^"]*?"\s+){2}([^\s]+\s+){2}"[^"]*?"\s+\d+\s+"[^"]*?"\s+(\d+\s+){2}"\w+\s+(\w+:\/+)?[^\/:]+(:\d+)?\/[^?]+({uri_query}\?.*?)\s+[^\s]+"""",
      """mwg:\s+Acces Denied\s+\[.+?\]\s+("[^"]*?"\s+){2}([^\s]+\s+){2}"[^"]*?"\s+\d+\s+"[^"]*?"\s+(\d+\s+){2}("[^"]*?"\s+){3}\d+\s+"(?:-|({category}[^,"]+))"""
      """mwg:\s+Acces Denied\s+\[.+?\]\s+("[^"]*?"\s+){2}([^\s]+\s+){2}"[^"]*?"\s+\d+\s+"[^"]*?"\s+(\d+\s+){2}("[^"]*?"\s+){3}\d+\s+"[^"]*?"\s+\d+\s+"(?:-|({action}[^"]+))"""",
      """mwg:\s+Acces Denied\s+\[.+?\]\s+("[^"]*?"\s+){2}([^\s]+\s+){2}"[^"]*?"\s+\d+\s+"[^"]*?"\s+(\d+\s+){2}("[^"]*?"\s+){3}\d+\s+"[^"]*?"\s+(\w+\s+"[^"]*?"\s+){3}("[^"]*?"\s+){2}"(?:|-|({user_agent}[^"]+?)\s*)("|$)"""
      """mwg:\s+Acces Denied\s+\[.+?\]\s+("[^"]*?"\s+){2}([^\s]+\s+){2}"[^"]*?"\s+\d+\s+"[^"]*?"\s+(\d+\s+){2}("[^"]*?"\s+){3}\d+\s+"[^"]*?"\s+(\w+\s+"[^"]*?"\s+){3}("[^"]*?"\s+){2}"(?:|-|({browser}[^"]+?)\s*)("|$)"""
      """mwg:\s+Acces Denied\s+\[.+?\]\s+("[^"]*?"\s+){2}([^\s]+\s+){2}"[^"]*?"\s+\d+\s+"[^"]*?"\s+(\d+\s+){2}("[^"]*?"\s+){3}\d+\s+"[^"]*?"\s+(\w+\s+"[^"]*?"\s+){3}("[^"]*?"\s+){2}"({browser}[\w\-]+)\/[\d\._]+"""
      """mwg:\s+Acces Denied\s+\[.+?\]\s+("[^"]*?"\s+){2}([^\s]+\s+){2}"[^"]*?"\s+\d+\s+"[^"]*?"\s+(\d+\s+){2}("[^"]*?"\s+){3}\d+\s+"[^"]*?"\s+(\w+\s+"[^"]*?"\s+){3}("[^"]*?"\s+){2}"({browser}[^\/;]+).+({os}iOS|Android|BlackBerry|WindowsPhone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)"""
      """Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
      """Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+)""",
    ]
  }
```