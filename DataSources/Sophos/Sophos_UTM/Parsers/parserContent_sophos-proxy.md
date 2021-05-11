#### Parser Content
```Java
{
Name = sophos-proxy
    Vendor = Sophos
    Product = Sophos UTM
    Lms = QRadar
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch_sec"
    Conditions = [ """req=""","""meth=""",""" t="""]
    Fields = [
		"""\st=({time}\d{1,100})""",
		"""\d\d:\d\d:\d\d ({host}[\w\-.]+)""",
		"""\starget_ip="({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
		"""\sh=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
		"""\ss=({result_code}\d{1,100})""",
		"""\su="(-|(({domain}[^\\]+)\\+)?({user}[^"]+))""",
		"""\sact=(-|({action}.+?))\s{1,100}(\w+=|$)""",
	        """exabeam_qidName=({proxy_action}.+?)\s{1,100}exabeam_""",
		"""\smeth="{0,20}(-|({method}[^"\s]+))""",
		"""\sout=(-|({bytes_out}\d{1,100}))""",
		"""\sin=(-|({bytes_in}\d{1,100}))""",
                """\sreq="(-|\w+\s{1,100}({full_url}\S+))""",
		"""\sreq="(-|(\w+\s{1,100}({protocol}[^:]+)))""",
		"""\sdom="(-|({web_domain}[^"]+))""",
		"""\sreq="(-|(\w+\s\w+:\/+[^\/]+\/({uri_path}[^?\s"]+)))""",
		"""\sreq="(-|(\w+\s\w+:\/+[^?]+({uri_query}\?[^\s"]+)))""",
		"""\stype="(-|({mime}[^"]+))""",
		"""\sua="(-|({user_agent}[^"]+))""",
		"""\scat="(-|0x2({risk_level}\d)({category}[^"]+))""",
     		"""\sua="(-|({browser}[\w\-]+))""",
     		"""\sua="(-|({browser}[\w\-]+)\/[\d\._]+)""",
     		"""\sua="(-|({browser}[^\/"]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
      		"""\sua="(-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
      		"""\sua="(-|Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d{1,100}\s{1,100}({browser}\w+))""",
                """\sdom="(.*?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s]+?(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+")[^"]+)""""
    ]
  }
```