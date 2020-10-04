#### Parser Content
```Java
{
Name = s-mwg-proxy-3
    Vendor = McAfee
    Product = McAfee Web Gateway
    Lms = Splunk
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
    Conditions = [ """exabeam_sourcetype=MWGaccess3""","""mwg: [""" ]
    Fields = [
      """exabeam_host=({host}[^\s]+)""",
      """\s+({host}[^\s]+)\s+mwg:""",
      """mwg:\s+\[({time}[^\]]+)\]""",
      """mwg:\s+\[.+?\]\s+"(?:|({user}[^"]+))"""",
      """mwg:\s+\[.+?\]\s+".*?"\s+({src_ip}[^\s]+)""",
      """mwg:\s+\[.+?\]\s+".*?"\s+[^\s]+\s+({result_code}\d+)""",
      """mwg:\s+\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+"({method}[^\s]+)""",
      """mwg:\s+\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+"\w+\s+(({protocol}\w+):\/+)?""",
      """mwg:\s+\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+"\w+\s+({full_url}(\w+:\/+)?({web_domain}(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^\/:]+))[^\s"]+)""",
      """mwg:\s+\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+"\w+\s+(\w+:\/+)?[^\/:]+:({dest_port}\d+)""",
      """mwg:\s+\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+"\w+\s+(\w+:\/+)?[^\/:]+(:\d+)?({uri_path}\/.*?)(\?|\s+[^\s]+")""",
      """mwg:\s+\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+"\w+\s+(\w+:\/+)?[^\/:]+(:\d+)?\/[^?]+({uri_query}\?.*?)\s+[^\s]+"""",
      """mwg:\s+\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+".*?"\s+"(?:-|({category}[^,"]+))""",
      """mwg:\s+\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+(".*?"\s+){3}"(?:|({mime}[^"]+))"""",
      """mwg:\s+\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+(".*?"\s+){4}({bytes_in}\d+)""",
      """mwg:\s+\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+(".*?"\s+){4}\d+\s+({bytes_out}\d+)""",
      """mwg:\s+\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+(".*?"\s+){4}(\d+\s+){2}"(?:|({user_agent}[^"]+))"""",
      """mwg:\s+\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+(".*?"\s+){4}(\d+\s+){2}"(?:|({browser}[^"]+))"""",
      """mwg:\s+\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+(".*?"\s+){4}(\d+\s+){2}"({browser}[\w\-]+)\/[\d\._]+""",
      """mwg:\s+\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+(".*?"\s+){4}(\d+\s+){2}"({browser}[^\/;]+).+({os}iOS|Android|BlackBerry|WindowsPhone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
      """Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
      """Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+)""",
      """mwg:\s+\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+(".*?"\s+){4}(\d+\s+){2}(".*?"\s+){4}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """"[A-Z]+\s+.*?({top_domain}(?!(?:\d+\.){3}\d+)[^\/,"\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\"|\/|\s|:))[^"\/\s:]+)""",
    ]
  }
```