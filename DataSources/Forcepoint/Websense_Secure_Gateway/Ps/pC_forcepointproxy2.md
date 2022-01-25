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
	    """exabeam_host=({host}[^\s]{1,2000})""",
            """({host}\S+)\s{1,100}vendor=""",
   	    """\sdst_ip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  	    """\ssrc_host=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
	    """\ssrc_port=({src_port}\d{1,100})""",
	    """\sdst_port=({dest_port}\d{1,100})""",
	    """user=[^=]{1,2000}?({user_ou}\w+=[^\/]{1,2000}?DC=\w+\/({user_fullname}[^\(]{1,2000}?))\s{1,100}(\([^\)]{1,2000}\)\s{1,100})?src_host=""",
	    """\saction=({action}[^\s]{1,2000})""",
	    """\shttp_method=(-|({method}[^\s]{1,2000}))""",
	    """\sbytes_in=({bytes_in}\d{1,100})""",
	    """\sbytes_out=({bytes_out}\d{1,100})""",
            """\surl=(?:-|({full_url}[^\s"]{1,2000}))""",
	    """\surl=(?:-|({protocol}[^:\s]{1,2000})):""",
	    """\surl=([^:]{1,2000}:\/+)?({web_domain}[^\s\/:]{1,2000})[^"]{0,2000}?$""",
	    """\surl=(?:-|\w+:\/+[^\s\/]{1,2000})\/+({uri_path}[^?\s]{0,2000})""",
	    """\surl=(?:-|(?=(?)(?:[^?]{1,2000}\?({uri_query}[^\s"]{1,2000}))))""",
	    """\shttp_user_agent=(?:-|({user_agent}[^=]{1,2000}?))\s{1,100}http_proxy""",
	    """\scategory=({category_id}\d{1,100})\s{1,100}user""",
	    """\shttp_content_type=(?:-|({mime}[^"]{1,2000}?))\s{1,100}http_""",
	    """\shttp_proxy_status_code=({result_code}\d{1,100})""",
            """\sdisposition=({disposition}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
            """\sreason=(-|({reason}[^=]{1,2000}?))\s{1,100}(\w+=|$)"""
    ]
  

}
```