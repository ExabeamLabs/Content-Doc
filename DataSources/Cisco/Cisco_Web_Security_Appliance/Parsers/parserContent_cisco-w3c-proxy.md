#### Parser Content
```Java
{
Name = cisco-w3c-proxy
    Vendor = Cisco
    Product = Cisco Web Security Appliance
    Lms = Splunk
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch_sec"
    Conditions = [ """cisco:webbrowsing"""]
    Fields = [
		"""({time}\d{10})\.\d{3}""",
		"""exabeam_host=({host}[^\s]+)""",
                """\d{10}\.\d{3}\s+[^\s]+\s(?:-|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\s([^\s]+\s){2}(?:-|"(({domain}[^\\]+)\\+)?({user}[^@"]+)[^"]*")\s(?:-|({bytes_out}\d+))\s(?:-|({bytes_in}\d+))\s(?:-|({result_code}\d+))\s(?:-|({proxy_action}[^\s]+))\s(?:-|({method}[^\s]+))\s(?:-|(({protocol}[^:]+):\/+)?({full_url}({web_domain}(?:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^\s\/:]+))(:({dest_port}\d+))?(?:-|({uri_path}\/[^?\s]*))?({uri_query}\?[^\s]+)?))\s(("[^"]+")|[^\s]+)\s+[^\s]+\s(?:-|({dest_ip}[^\s]+))\s([^\s]+\s){2}(?:-|"({category}[^"]+)")\s[^\s]+\s(?:-|({mime}[^\s]+))\s(("[^"]+")|[^\s]+)\s(?:-|"({user_agent}[^"]+)")\s(?:-|({action}[^-\s]+))""",
		"""\d{10}\.\d{3}\s+([^\s]+\s){11}".+?"\s+([^\s]+\s+){4}".+?"(\s[^\s]+){3}\s+"(?:[\s-]|({browser}[^"]+))""",
		"""\d{10}\.\d{3}\s+([^\s]+\s){11}".+?"\s+([^\s]+\s+){4}".+?"(\s[^\s]+){3}\s+"(?:[\s-]|({browser}[\w\-]+)\/[\d\._]+)""",
		"""\d{10}\.\d{3}\s+([^\s]+\s){11}".+?"\s+([^\s]+\s+){4}".+?"(\s[^\s]+){3}\s+"(?:[\s-]|({browser}[^\/;]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
		"""Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
		"""Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+)""",
		"""\d{10}\.\d{3}\s+([^\s]+\s){10}(\w+:\/+)?(?:-|(.*?)({top_domain}(?!(?:\d+\.){3}\d+)[^:\/\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\s|\/|:))[^\s\/:]+))"""
    ]
  }
```