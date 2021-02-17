#### Parser Content
```Java
{
Name = mwg-proxy-2
    Vendor = McAfee
    Product = McAfee Web Gateway
    Lms = Splunk
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
    Conditions = [ """exabeam_sourcetype=webproxy""","""mwg:""" ]
    Fields = [
		"""\[({time}[^\]]+)""",
		"""exabeam_host=({host}[^\s]+)""",
		"""\d\d:\d\d:\d\d\s+({host}[^\s]+)\s+mwg:""",
		"""\[.+?\]\s+"(?:|({user}[^"]+))"""",
		"""\[.+?\]\s+".*?"\s+({src_ip}[^\s]+)""",
		"""\[.+?\]\s+".*?"\s+[^\s]+\s+({result_code}\d+)""",
		"""\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+"({method}[^\s]+)""",
		"""\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+"\w+\s+(({protocol}\w+):\/+)?""",
                """\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+"\w+\s+({full_url}\S+)""",
		"""\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+"\w+\s+(\w+:\/+)?({web_domain}(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^\/:]+))""",
		"""\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+"\w+\s+(\w+:\/+)?[^\/:]+:({dest_port}\d+)""",
		"""\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+"\w+\s+(\w+:\/+)?[^\/:]+(:\d+)?({uri_path}\/.*?)(\?|\s+[^\s]+")""",
		"""\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+"\w+\s+(\w+:\/+)?[^\/:]+(:\d+)?\/[^?]+({uri_query}\?.*?)\s+[^\s]+"""",
		"""\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+".*?"\s+"(?:-|({category}[^,"]+))""",
		"""\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+(".*?"\s+){3}"(?:|({mime}[^"]+))"""",
		"""\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+(".*?"\s+){4}"(?:|({user_agent}[^"]+))"""",
		"""\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+(".*?"\s+){4}"(?:|({browser}[^"]+))"""",
		"""\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+(".*?"\s+){4}"({browser}[\w\-]+)\/[\d\._]+""",
		"""\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+(".*?"\s+){4}"({browser}[^\/;]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
		"""Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
		"""Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+)""",
		"""\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+(".*?"\s+){6}\d+\s+({dest_ip}[^\s]+)""",
		"""\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+(".*?"\s+){6}([^\s]+\s+){2}({bytes_in}\d+)""",
		"""\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+(".*?"\s+){6}([^\s]+\s+){3}({bytes_out}\d+)""",
		"""\[.+?\]\s+".*?"\s+[^\s]+\s+\d+\s+(".*?"\s+){6}([^\s]+\s+){6}"(?:|({failure_reason}[^"]+))"""",
		""""[A-Z]+\s+.*?({top_domain}(?!(?:\d+\.){3}\d+)[^\/,"\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\"|\/))[^"\/]+)"""
    ]
  }
```