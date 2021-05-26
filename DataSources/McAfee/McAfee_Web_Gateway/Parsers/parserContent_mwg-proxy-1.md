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
		""""timestamp":"\[({time}[^\]]{1,2000})""",
		"""exabeam_host=({host}[^\s]{1,2000})""",
		"""\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s{1,100}mwg:""",
		""""user":"(?:|({user}[^"]{1,2000}))"""",
		""""src":"(?:|({src_ip}[^"]{1,2000}))"""",
		""""status":"(?:|({result_code}[^"]{1,2000}))"""",
		""""protocol":"(?:|({protocol}[^"]{1,2000}))"""",
		""""http_user_agent":"(?:|({user_agent}[^"]{1,2000}))"""",
		""""http_user_agent":"(?:|({browser}[^"]{1,2000}))"""",
		""""http_user_agent":"({browser}[\w\-]{1,2000})\/[\d\._]{1,2000}""",
		""""http_user_agent":"({browser}[^\/";]{1,2000}).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
		"""Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
		"""Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d{1,100}\s{1,100}({browser}\w+)""",
		""""http_method":"(?:|({method}[^"]{1,2000}))"""",
		""""domain":"(.*?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\"|\/))[^"\/]{1,2000})""",
                """"url":"(?:|({full_url}[^"]{1,2000}))"""",
		""""domain_full":"(?:|({web_domain}[^"]{1,2000}))"""",
		""""category":"(?:|({category}[^"]{1,2000}))"""",
		""""bytes_in":"(?:|({bytes_in}[^"]{1,2000}))"""",
		""""bytes_out":"(?:|({bytes_out}[^"]{1,2000}))"""",
		""""cache_status":"(?:|({proxy_action}[^"]{1,2000}))"""",
		""""block_reason":"(?:|({failure_reason}[^"]{1,2000}))"""",
		""""dest":"(?:|({dest_ip}[^"]{1,2000}))"""",
		""""dest_port":"(?:|({dest_port}[^"]{1,2000}))"""",
		""""is_virus":"(?:|({malicious}[^"]{1,2000}))"""",
		""""content_type":"(?:|({mime}[^"]{1,2000}))""""
    ]
  }
```