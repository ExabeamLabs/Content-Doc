#### Parser Content
```Java
{
Name = forcepoint-proxy-1
    Vendor = Forcepoint
    Product = Websense Secure Gateway
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ "vendor=Forcepoint","""http_user_agent=""","""http_proxy_status_code="""]
    Fields = [
	    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
        """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}[\+\-]\d{1,100}:\d{1,100})""",
	    """exabeam_host=({host}[^\s]{1,2000})""",
        """({host}\S+)\s{1,100}vendor=""",
   	    """\sdst_ip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  	    """\ssrc_host=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
	    """\ssrc_port=({src_port}\d{1,100})""",
	    """\sdst_port=({dest_port}\d{1,100})""",
      """user=.+?({user_ou}OU\\?=.+?)\s{1,100}(\w+=|$)""",
      """user=.+?DC\\?=\w+/(({user_email}[^@=\s]{1,2000}@[^@=]{1,2000}?)|({user_fullname}[^@=]{1,2000}?)(@[^@=]{0,2000}?)?)(\s{1,100}\w+=|\s{0,100}$)""",
	    """\saction=({action}[^\s]{1,2000})""",
	    """\shttp_method=(-|({method}[^\s]{1,2000}))""",
	    """\sbytes_in=({bytes_in}\d{1,100})""",
	    """\sbytes_out=({bytes_out}\d{1,100})""",
        """\surl=(?:-|({full_url}[^\s"]{1,2000}))""",
	    """\surl=(?:-|({protocol}[^:]{1,2000}))""",
	    """\surl=([^:]{1,2000}:\/+)?({web_domain}[^\s\/:]{1,2000}).*?$""",
	    """\surl=(?:-|\w+:\/+[^\s\/]{1,2000})({uri_path}\/[^?\s]{0,2000})""",
	    """\surl=(?:-|(?=(?)(?:[^?]{1,2000}({uri_query}\?[^\s"]{1,2000}))))""",
	    """\shttp_user_agent=(?:-|({user_agent}.+?))\s{1,100}http_proxy""",
	    """\scategory=({category_id}.+?)\s{1,100}user""",
	    """\shttp_content_type=(?:-|({mime}.+?))\s{1,100}http_""",
	    """\shttp_proxy_status_code=({result_code}\d{1,100})""",
      """\WloginID=(-|({user}[^\s]{1,2000}))""",
    ]
  

}
```