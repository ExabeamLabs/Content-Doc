#### Parser Content
```Java
{
Name = mwg-proxy-1
    Vendor = McAfee
    Product = McAfee Web Gateway
    Lms = Splunk
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
    Conditions = [ """"file_sha256_hash":""",""""domain_full":""","""mwg:"""]
    Fields = [
		""""timestamp":"\[({time}[^\]]+)""",
		"""exabeam_host=({host}[^\s]+)""",
		"""\d\d:\d\d:\d\d\s+({host}[^\s]+)\s+mwg:""",
		""""user":"(?:|({user}[^"]+))"""",
		""""src":"(?:|({src_ip}[^"]+))"""",
		""""status":"(?:|({result_code}[^"]+))"""",
		""""protocol":"(?:|({protocol}[^"]+))"""",
		""""http_user_agent":"(?:|({user_agent}[^"]+))"""",
		""""http_user_agent":"(?:|({browser}[^"]+))"""",
		""""http_user_agent":"({browser}[\w\-]+)\/[\d\._]+""",
		""""http_user_agent":"({browser}[^\/";]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
		"""Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
		"""Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+)""",
		""""http_method":"(?:|({method}[^"]+))"""",
		""""domain":"(.*?)({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\"|\/))[^"\/]+)""",
                """"url":"(?:|({full_url}[^"]+))"""",
		""""domain_full":"(?:|({web_domain}[^"]+))"""",
		""""category":"(?:|({category}[^"]+))"""",
		""""bytes_in":"(?:|({bytes_in}[^"]+))"""",
		""""bytes_out":"(?:|({bytes_out}[^"]+))"""",
		""""cache_status":"(?:|({proxy_action}[^"]+))"""",
		""""block_reason":"(?:|({failure_reason}[^"]+))"""",
		""""dest":"(?:|({dest_ip}[^"]+))"""",
		""""dest_port":"(?:|({dest_port}[^"]+))"""",
		""""is_virus":"(?:|({malicious}[^"]+))"""",
		""""content_type":"(?:|({mime}[^"]+))""""
    ]
  }
```