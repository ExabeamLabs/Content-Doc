#### Parser Content
```Java
{
Name = cisco-wsa-squid-proxy
    Vendor = Cisco
    Product = Cisco Secure Web Appliance
    Lms = Splunk
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch_sec"
    Conditions = [ """cisco:wsa:squid"""]
    Fields = [
		"""({time}\d{10})\.\d{3}""",
		"""exabeam_host=({host}[^\s]+)""",
		"""\s{1,100}({host}[^\s:]+):?\s{1,100}Info:""",
		"""\d{10}\.\d{3}\s{1,100}[^\s]+\s(?:-|({src_ip}[^\s]+))""",
		"""\d{10}\.\d{3}\s{1,100}([^\s]+\s){2}(?:-|({proxy_action}.+?)(\/(?:-|({result_code}\d{1,100})))?)\s{1,100}""",
		"""\d{10}\.\d{3}\s{1,100}([^\s]+\s){4}(?:-|({method}[^\s]+))""",
        """\d{10}\.\d{3}\s{1,100}([^\s]+\s){5}(?:-|({full_url}(({protocol}[^:]+):\/+)?[^\s:\/]+(:({dest_port}\d{1,100}))?\/(?:-|({uri_path}[^?\s]+))?({uri_query}\?[^\s]+)?))""",
		"""\d{10}\.\d{3}\s{1,100}([^\s]+\s){6}"{1,20}(?:-|({domain}[^\\]+)\\+({user}[^@"]+))""",
		"""\d{10}\.\d{3}\s{1,100}([^\s]+\s){5}(\w+:\/+)?({web_domain}(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^\s\/:]+))""",
		"""\d{10}\.\d{3}\s{1,100}([^\s]+\s){9}(?:-|({action}[^\s-]+))""",
		"""\d{10}\.\d{3}\s{1,100}([^\s]+\s){8}(?:-|({mime}[^\s]+))""",
		"""\d{10}\.\d{3}\s{1,100}([^\s]+\s){10}.*?"\s{1,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}"""",
		"""\s{1,100}<.+?>.+?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s{1,100}".+?"\s{1,100}"({category}[^"]+)""",
		"""\d{10}\.\d{3}\s{1,100}([^\s]+\s){9}[^\s]+\s{1,100}<(?:-|nc|({category}[^,>]+))""",
		"""\d{10}\.\d{3}\s{1,100}([^\s]+\s){9}[^\s]+\s{1,100}<[^>]+>\s{1,100}[^\s]+\s{1,100}"{1,20}(?:[\s-]|({user_agent}[^"]+))""",
		"""\d{10}\.\d{3}\s{1,100}([^\s]+\s){9}[^\s]+\s{1,100}<[^>]+>\s{1,100}[^\s]+\s{1,100}"{1,20}(?:[\s-]|({browser}[^"]+))""",
		"""\d{10}\.\d{3}\s{1,100}([^\s]+\s){9}[^\s]+\s{1,100}<[^>]+>\s{1,100}[^\s]+\s{1,100}"{1,20}(?:[\s-]|({browser}[\w\-]+)\/[\d\._]+)""",
		"""\d{10}\.\d{3}\s{1,100}([^\s]+\s){9}[^\s]+\s{1,100}<[^>]+>\s{1,100}[^\s]+\s{1,100}"{1,20}(?:[\s-]|({browser}[^\/;]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
		""""Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
		""""Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d{1,100}\s{1,100}({browser}\w+)""",
		"""\d{10}\.\d{3}\s{1,100}([^\s]+\s){5}(\d{1,100}\/)?(\w+:\/+)(?:-|(.*?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^=,"\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\s|\/))[^\s\/]+))"""
    ]
  }
```