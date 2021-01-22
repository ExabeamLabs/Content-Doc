#### Parser Content
```Java
{
Name = s-zscaler-web-activity-3
  Vendor = Zscaler
  Product = Zscaler
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "MMM  dd HH:mm:ss yyyy"
  Conditions = [ """login=""", """cip=""", """eurl=""", """urlsupercat=""", """action=""" ]
  Fields = [
    """epochtime=({time}\d+)""",
    """ehost=({host}[^\s]+)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"time=\w+\s+({time}\w+\s+\d+\s+\d+:\d+:\d+\s+\d+)""",
    """login=({user_email}({user}[^@\s"]+)@[^@\s"]+)""",
    """(\W|")reason=({proxy_action}[^="]+?)("|\s+\w+=)""",
    """(\s|")action=({action}[^="]+?)("|\s+\w+=)""",
    """(\W|")reqmethod=(NA|({method}[^"=]+?))("|\s+\w+=)""",
    """(\W|")cip=({src_ip}[A-Fa-f:\d.]+)""",
    """(\W|")sip=({dest_ip}[A-Fa-f:\d.]+)""",
    """(\W|")proto=({protocol}[^="]+?)("|\s+\w+=)""",
    """(\W|")eurl=((\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({web_domain}[^\/:"]+))(:({dest_port}\d+))?({uri_path}[^?"\s]+)?(\?({uri_query}[^,]+))?","""
    """(\W|")eurl=({full_url}[^="]+)("|\s\w+=)""",
    """(\W|")urlsupercat=({category}[^+=]+?)("|\s+\w+=)""",
    """(\W|")eurl=[^"]+?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""",
    """(\W|")ua=(Unknown|({user_agent}[^"=]+?))("|\s+\w+=)""",
    """reqsize=({bytes_out}\d+)""",
    """respsize=({bytes_in}\d+)""",
    """respcode=({result_code}\d+)""",
    """(\W|")ereferer=(None|({referer}[^="]+?))\s*(\w+=|"|$)""",
    """"appname=({app}[^"]+)""",
    """"appclass=({app_class}[^"]+)""",
    """"dlpdict=(None|({dlp_dict}[^"]+))""",
    """"dlpeng=(None|({dlp_eng}[^"]+))""",
    """"location=(None|({location}[^"]+))""",
    """"dept=(None|({department}[^"]+))""",
    """"malwarecat=(None|({malware_category}[^"]+))"""
    ]
}
```