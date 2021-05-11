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
    """ehost=({host}[^\s]+)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"time=\w+\s{1,100}({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}\d{1,100})""",
    """login=({user_email}({user}[^@\s"]+)@[^@\s"]+)""",
    """(\W|")reason=({proxy_action}[^="]+?)("|\s{1,100}\w+=)""",
    """(\s|")action=({action}[^="]+?)("|\s{1,100}\w+=)""",
    """(\W|")reqmethod=(NA|({method}[^"=]+?))("|\s{1,100}\w+=)""",
    """(\W|")cip=({src_ip}[A-Fa-f:\d.]+)""",
    """(\W|")sip=({dest_ip}[A-Fa-f:\d.]+)""",
    """(\W|")proto=({protocol}[^="]+?)("|\s{1,100}\w+=)""",
    """(\W|")eurl=((\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({web_domain}[^\/:"]+))(:({dest_port}\d{1,100}))?({uri_path}[^?"\s]+)?(\?({uri_query}[^,]+))?","""
    """(\W|")eurl=({full_url}[^="]+)("|\s\w+=)""",
    """(\W|")urlsupercat=({category}[^+=]+?)("|\s{1,100}\w+=)""",
    """(\W|")eurl=[^"]+?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""",
    """(\W|")ua=(Unknown|({user_agent}[^"=]+?))("|\s{1,100}\w+=)""",
    """reqsize=({bytes_out}\d{1,100})""",
    """respsize=({bytes_in}\d{1,100})""",
    """respcode=({result_code}\d{1,100})""",
    """(\W|")ereferer=(None|({referer}[^="]+?))\s{0,100}(\w+=|"|$)""",
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