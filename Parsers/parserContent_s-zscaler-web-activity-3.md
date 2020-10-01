#### Parser Content
```Java
{
Name = s-zscaler-web-activity-3
  Vendor = Zscaler
  Product = Zscaler
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """login=""", """cip=""", """eurl=""", """urlsupercat=""", """action=""" ]
  Fields = [
    """epochtime=({time}\d+)""",
    """ehost=({host}[^\s]+)""",
    """login=({user_email}({user}[^@\s"]+)@[^@\s"]+)""",
    """reason=({proxy_action}.+?)\s+\w+=""",
    """\saction=({action}.+?)\s+ssldecrypted=""",
    """reqmethod=(NA|({method}.+?))\s+\w+=""",
    """cip=({src_ip}[A-Fa-f:\d.]+)""",
    """sip=({dest_ip}[A-Fa-f:\d.]+)""",
    """proto=({protocol}.+?)\s+\w+=""",
    """eurl=({web_domian}[^\/:]+)\/*:*({dest_port}\d+)?({uri_path}[^?\s]+)?(\?({uri_query}.+?))?\s+ereferer=""",
    """eurl=({full_url}.+?)\s\w+=""",
    """urlsupercat=({category}.+?)\s+\w+=""",
    """eurl=[^"]+?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""",
    """ua=({user_agent}.+?)\s+\w+=""",
    """reqsize=({bytes_out}\d+)""",
    """respsize=({bytes_in}\d+)""",
    """respcode=({result_code}\d+)""",
    """ereferer=(None|({referer}.+?))\s+(\w+=|$)""",
    ]
}
```