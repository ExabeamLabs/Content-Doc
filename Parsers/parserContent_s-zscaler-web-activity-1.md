#### Parser Content
```Java
{
Name = s-zscaler-web-activity-1
  Vendor = Zscaler
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ ""","ologin":"""", ""","cip":"""", ""","url":"""", ""","urlsupercat":"""", ""","reqdatasize":""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"time":"({time}\d\d\d\d-\d\d-\d\d \d+:\d+:\d+)""",
    """"ologin":"({user_email}({user}[^@\s"]+)@[^@\s"]+)"""",
    """"cip":"({src_ip}[A-Fa-f:\d.]+)""",
    """"proto":"({protocol}[^"]+)""",
    """"reqmethod":"({method}[^"]+)""",
    """"url":"({full_url}[^"]+)""",
    """"url":"(?:[^:]+:\/+)?({web_domain}[^\/:\s"]+)({uri_path}\/[^\?"]+)?({uri_query}\?[^"]+)?""",
    """"url":"[^"]+?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""",
    """"respcode":"({result_code}[^"]+)""",
    """"sip":"({dest_ip}[^"]+)""",
    """"action":"({action}[^"]+)""",
    """"reason":"({proxy_action}[^"]+)""",
    """"urlsupercat":"({category}[^"]+)""",
    """"ua":"({user_agent}[^"]+)""",
    """"ua":"(?:-|Mozilla\/[^"]+?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """"referer":"({referrer}[^"]+)""",
    """"fileclass":"({mime}[^"]+)""",
    """"reqdatasize":({bytes_out}\d+)""",
    """"respdatasize":({bytes_in}\d+)""",
  ]
}
```