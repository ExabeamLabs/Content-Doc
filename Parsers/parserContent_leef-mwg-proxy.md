#### Parser Content
```Java
{
Name = leef-mwg-proxy
    Vendor = McAfee
    Product = McAfee Web Gateway
    Lms = QRadar
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """LEEF:""","""|McAfee|Web Gateway|""" ]
    Fields = [
		"""\|devTime=({time}\d+)""",
		"""\d\d:\d\d:\d\d\s({host}[^\s]+)\s(mwg:\s)?LEEF:""",
		"""\|usrName=(?:|({user}[^|]+))\|""",
		"""\|src=(?:|({src_ip}[^|]+))\|""",
		"""\|dst=(?:|({dest_ip}[^|]+))\|""",
		"""\|httpStatus=(?:|({result_code}[^|]+))\|""",
		"""\|Prot=(?:|({protocol}[^|]+))\|""",
		"""\|(?:agent|usrAgent)=(?:|({user_agent}[^|]+))\|""",
		"""\|(?:agent|usrAgent)=(?:|({browser}[^|]+))\|""",
		"""\|(?:agent|usrAgent)=({browser}[\w\-]+)\/[\d\._]+""",
		"""\|(?:agent|usrAgent)=({browser}[^\/";]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
		"""Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
		"""Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+)""",
		"""\|Meth=(?:|({method}[^|]+))\|""",
        """\|url=(-|({full_url}.+?))(\|\w+=|\"|\s*$|$)""",
		"""\|url=(.*?)({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\||\/))[^|\/]+)""",
		"""\|url=(?:|(\w+:\/+)?({web_domain}(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^\/:|]+))[^|]*)(\||\"|\s*$|$)""",
		"""\|url=(?:|(\w+:\/+)?[^|\/:]+(:\d+)?({uri_path}\/[^?"|]+)[^|]*)(\||\"|\s*$|$)""",
		"""\|url=(?:|(\w+:\/+)?[^|\/:]+(:\d+)?[^|?]+({uri_query}\?.+?))(\|\w+=|\"|\s*$|$)""",
		"""\|urlCategories=(?:|({category}[^,|]+))(,|\|)""",
		"""\|(?:recv|BtS|dstBytes)=({bytes_in}\d+)""",
		"""\|(?:sent|BfS|srcBytes)=({bytes_out}\d+)""",
		"""\|blockReason=(?:|\s*({failure_reason}[^\s|][^|]+?)\s*)\|""",
        """\|blockReason=(?:|\s*({action}[^\s|][^|]+?)\s*)\|""",
		"""\|blockReason=(?:|[^|]+by ({action}[^|]+))\|""",
		"""\|mal=(?:|({malicious}[^|]+))\|""",
		"""\|(?:mType|mime)=(?:|({mime}.+?))\s*(\||$)"""
    ]
  }
```