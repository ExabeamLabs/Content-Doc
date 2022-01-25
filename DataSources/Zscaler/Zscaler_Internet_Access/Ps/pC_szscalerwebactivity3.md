#### Parser Content
```Java
{
Name = s-zscaler-web-activity-3
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "MMM  dd HH:mm:ss yyyy"
  Conditions = [ """login=""", """cip=""", """eurl=""", """urlsupercat=""", """action=""" ]
  Fields = [
    """epochtime=({time}\d{1,100})""",
    """ehost=({host}[^\s]{1,2000})""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"time=\w+\s{1,100}({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}\d{1,100})""",
    """login=({user_email}({user}[^@\s"]{1,2000})@[^@\s"]{1,2000})""",
    """(\W|")reason=({proxy_action}[^="]{1,2000}?)("|\s{1,100}\w+=)""",
    """(\s|")action=({action}[^="]{1,2000}?)("|\s{1,100}\w+=)""",
    """(\W|")reqmethod=(NA|({method}[^"=]{1,2000}?))("|\s{1,100}\w+=)""",
    """(\W|")cip=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """(\W|")sip=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """(\W|")proto=({protocol}[^="]{1,2000}?)("|\s{1,100}\w+=)""",
    """(\W|")eurl=((\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({web_domain}[^\/:"]{1,2000}))(:({dest_port}\d{1,100}))?({uri_path}[^?"\s]{1,2000})?(\?({uri_query}[^,]{1,2000}))?","""
    """(\W|")eurl=({full_url}[^="]{1,2000})("|\s\w+=)""",
    """(\W|")urlsupercat=({category}[^+=]{1,2000}?)("|\s{1,100}\w+=)""",
    """(\W|")ua=(Unknown|({user_agent}[^"=]{1,2000}?))("|\s{1,100}\w+=)""",
    """reqsize=({bytes_out}\d{1,100})""",
    """respsize=({bytes_in}\d{1,100})""",
    """respcode=({result_code}\d{1,100})""",
    """(\W|")ereferer=(None|({referer}[^="]{1,2000}?))\s{0,100}(\w+=|"|$)""",
    """"appname=({app}[^"]{1,2000})""",
    """"appclass=({app_class}[^"]{1,2000})""",
    """"dlpdict=(None|({dlp_dict}[^"]{1,2000}))""",
    """"dlpeng=(None|({dlp_eng}[^"]{1,2000}))""",
    """"location=(None|({location}[^"]{1,2000}))""",
    """"dept=(None|({department}[^"]{1,2000}))""",
    """"malwarecat=(None|({malware_category}[^"]{1,2000}))"""
    ]


}
```