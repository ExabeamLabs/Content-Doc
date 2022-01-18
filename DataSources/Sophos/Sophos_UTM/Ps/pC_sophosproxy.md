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
		"""\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000})""",
		"""\starget_ip="({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
		"""\sh=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
		"""\ss=({result_code}\d{1,100})""",
		"""\su="(-|(({domain}[^\\]{1,2000})\\+)?({user}[^"]{1,2000}))""",
		"""\sact=(-|({action}.+?))\s{1,100}(\w+=|$)""",
	        """exabeam_qidName =({proxy_action}.+?)\s{1,100}exabeam_""",
		"""\smeth="{0,20}(-|({method}[^"\s]{1,2000}))""",
		"""\sout=(-|({bytes_out}\d{1,100}))""",
		"""\sin=(-|({bytes_in}\d{1,100}))""",
                """\sreq="(-|\w+\s{1,100}({full_url}\S+))""",
		"""\sreq="(-|(\w+\s{1,100}({protocol}[^:]{1,2000})))""",
		"""\sdom="(-|({web_domain}[^"]{1,2000}))""",
		"""\sreq="(-|(\w+\s\w+:\/+[^\/]{1,2000}\/({uri_path}[^?\s"]{1,2000})))""",
		"""\sreq="(-|(\w+\s\w+:\/+[^?]{1,2000}({uri_query}\?[^\s"]{1,2000})))""",
		"""\stype="(-|({mime}[^"]{1,2000}))""",
		"""\sua="(-|({user_agent}[^"]{1,2000}))""",
		"""\scat="(-|0x2({risk_level}\d)({category}[^"]{1,2000}))""",
     		"""\sua="(-|({browser}[\w\-]{1,2000}))""",
     		"""\sua="(-|({browser}[\w\-]{1,2000})\/[\d\._]{1,2000})""",
     		"""\sua="(-|({browser}[^\/"]{1,2000}).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
      		"""\sua="(-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
      		"""\sua="(-|Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d{1,100}\s{1,100}({browser}\w+))""",
                """\sdom="(.*?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s]{1,2000}?(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+")[^"]{1,2000})""""
    ]
  

}
```