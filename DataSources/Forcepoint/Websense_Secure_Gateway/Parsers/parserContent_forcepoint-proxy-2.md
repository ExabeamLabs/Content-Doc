#### Parser Content
```Java
{
Name = forcepoint-proxy-2
    Vendor = Forcepoint
    Product = Websense Secure Gateway
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """vendor=Websense""","""http_user_agent=""","""http_proxy_status_code="""]
    Fields = [
	    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
	    """exabeam_host=({host}[^\s]+)""",
            """({host}\S+)\s{1,100}vendor=""",
   	    """\sdst_ip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  	    """\ssrc_host=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
	    """\ssrc_port=({src_port}\d{1,100})""",
	    """\sdst_port=({dest_port}\d{1,100})""",
	    """user=[^=]+?({user_ou}\w+=[^\/]+?DC=\w+\/({user_fullname}[^\(]+?))\s{1,100}(\([^\)]+\)\s{1,100})?src_host=""",
	    """\saction=({action}[^\s]+)""",
	    """\shttp_method=(-|({method}[^\s]+))""",
	    """\sbytes_in=({bytes_in}\d{1,100})""",
	    """\sbytes_out=({bytes_out}\d{1,100})""",
            """\surl=(?:-|({full_url}[^\s"]+))""",
	    """\surl=(?:-|({protocol}[^:\s]+)):""",
	    """\surl=([^:]+:\/+)?({web_domain}[^\s\/:]+)[^"]*?$""",
	    """\surl=(?:-|\w+:\/+[^\s\/]+)\/+({uri_path}[^?\s]*)""",
	    """\surl=(?:-|(?=(?)(?:[^?]+\?({uri_query}[^\s"]+))))""",
	    """\shttp_user_agent=(?:-|({user_agent}[^=]+?))\s{1,100}http_proxy""",
	    """\scategory=({category_id}\d{1,100})\s{1,100}user""",
	    """\shttp_content_type=(?:-|({mime}[^"]+?))\s{1,100}http_""",
	    """\shttp_proxy_status_code=({result_code}\d{1,100})""",
	    """\surl=([^"]*?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\s|\/|$))[^\s\/]+)""",
	    """\shttp_user_agent=(?:-|({browser}[\w\-]+))[^=]+?http_proxy""",
	    """\shttp_user_agent=(?:-|({browser}[\w\-]+)\/[\d\._]+)[^=]+?http_proxy""",
	    """\shttp_user_agent=(?:-|({browser}[^\/]+)[^=]+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))[^=]+?http_proxy""",
	    """\shttp_user_agent=(?:-|Mozilla\/[^=]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))[^=]+?http_proxy""",
	    """\shttp_user_agent=(?:-|Mozilla\/[^=]+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]+Gecko\/\d{1,100}\s{1,100}({browser}\w+))[^=]+?http_proxy""",
            """\sdisposition=({disposition}[^=]+?)\s{1,100}(\w+=|$)""",
            """\sreason=(-|({reason}[^=]+?))\s{1,100}(\w+=|$)"""
    ]
  }
```