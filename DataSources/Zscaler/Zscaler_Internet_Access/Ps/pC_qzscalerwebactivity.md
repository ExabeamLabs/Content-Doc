#### Parser Content
```Java
{
Name = q-zscaler-web-activity
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = QRadar
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Zscaler|NSS|""", """|cat=""" ]
  Fields = [
    """devTime=({time}\w+ \d{1,100} \d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """src=({src_ip}[a-fA-F\d:\.]{1,2000})""",
    """dst=(0\.0\.0\.0|({dest_ip}[a-fA-F\d:\.]{1,2000}))""",
    """usrName =({user_email}[^\s@]{1,2000}@[^=\|]{1,2000}?)\s{0,100}(\w+=|\|)""",
    """cat=({action}[^\s\|]{1,2000})""",
    """policy=({proxy_action}[^=\|]{1,2000}?)\s{0,100}(\w+=|$|\|)""",
    """urlcategory=({categories}({category}[^=\|]{1,2000}?))\s{0,100}(\w+=|$|\|)""",
    """url=({full_url}[^\s\|]{1,2000})""",
    """url=(\w+:\/{2})?[^\/\s\|]{1,2000}({uri_path}\/[^?\s]{1,2000})""",
    """url=(\w+:\/+)?[^|\/:\s]{1,2000}(:\d{1,100})?[^|?\s]{1,2000}({uri_query}\?[^\s\|]{1,2000})""",
    """url=(?:[^:?]{1,2000}:\/+)?({web_domain}[^\/:\s\|]{1,2000})(:({dest_port}\d{1,100}))?""",
    """srcBytes=({bytes_out}\d{1,100})""",
    """dstBytes=({bytes_in}\d{1,100})""",
    """appproto=({protocol}[^=\|]{1,2000}?)\s{0,100}(\w+=|$|\|)""",
    """appname=({app}[^=]{1,2000}?)\s{0,100}(\w+=|$|\|)""",
    """useragent=(Unknown|({user_agent}[^=\|]{1,2000}?))\s{0,100}(\w+=|$|\|)""",
    """respcode=({result_code}\d{1,100})""",
    """reqmethod=(NA|({method}[^=\|]{1,2000}?))\s{0,100}(\w+=|$|\|)""",
    """fileclass=(None|({mime}[^=\|]{1,2000}?))\s{0,100}(\w+=|$|\|)""",
    """referer=(None|({referrer}[^\s\|]{1,2000}?))\s{0,100}(\w+=|$|\|)""",
    """riskscore=({risk_level}\d{1,100})""",
   ]


}
```