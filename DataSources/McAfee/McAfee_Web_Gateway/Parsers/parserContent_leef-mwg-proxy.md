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
		"""\|devTime=({time}\d{1,100})""",
		"""\d\d:\d\d:\d\d\s({host}[^\s]{1,2000})\s(mwg:\s)?LEEF:""",
		"""\|usrName=(?:|({user}[^|]{1,2000}))\|""",
		"""\|src=(?:|({src_ip}[^|]{1,2000}))\|""",
		"""\|dst=(?:|({dest_ip}[^|]{1,2000}))\|""",
		"""\|httpStatus=(?:|({result_code}[^|]{1,2000}))\|""",
		"""\|Prot=(?:|({protocol}[^|]{1,2000}))\|""",
		"""\|(?:agent|usrAgent)=(?:|({user_agent}[^|]{1,2000}))\|""",
		"""\|(?:agent|usrAgent)=(?:|({browser}[^|]{1,2000}))\|""",
		"""\|(?:agent|usrAgent)=({browser}[\w\-]{1,2000})\/[\d\._]{1,2000}""",
		"""\|(?:agent|usrAgent)=({browser}[^\/";]{1,2000}).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
		"""Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
		"""Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d{1,100}\s{1,100}({browser}\w+)""",
		"""\|Meth=(?:|({method}[^|]{1,2000}))\|""",
        """\|url=(-|({full_url}.+?))(\|\w+=|\"|\s{0,100}$|$)""",
		"""\|url=(.*?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\||\/))[^|\/]{1,2000})""",
		"""\|url=(?:|(\w+:\/+)?({web_domain}(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^\/:|]{1,2000}))[^|]{0,2000})(\||\"|\s{0,100}$|$)""",
		"""\|url=(?:|(\w+:\/+)?[^|\/:]{1,2000}(:\d{1,100})?({uri_path}\/[^?"|]{1,2000})[^|]{0,2000})(\||\"|\s{0,100}$|$)""",
		"""\|url=(?:|(\w+:\/+)?[^|\/:]{1,2000}(:\d{1,100})?[^|?]{1,2000}({uri_query}\?.+?))(\|\w+=|\"|\s{0,100}$|$)""",
		"""\|urlCategories=(?:|({category}[^,|]{1,2000}))(,|\|)""",
		"""\|(?:recv|BtS|dstBytes)=({bytes_in}\d{1,100})""",
		"""\|(?:sent|BfS|srcBytes)=({bytes_out}\d{1,100})""",
		"""\|blockReason=(?:|\s{0,100}({failure_reason}[^\s|][^|]{1,2000}?)\s{0,100})\|""",
        """\|blockReason=(?:|\s{0,100}({action}[^\s|][^|]{1,2000}?)\s{0,100})\|""",
		"""\|blockReason=(?:|[^|]{1,2000}by ({action}[^|]{1,2000}))\|""",
		"""\|mal=(?:|({malicious}[^|]{1,2000}))\|""",
		"""\|(?:mType|mime)=(?:|({mime}.+?))\s{0,100}(\||$)"""
    ]
  }
```