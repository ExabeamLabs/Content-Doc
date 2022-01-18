#### Parser Content
```Java
{
Name = s-symantec-web-activity-1
  Vendor = Symantec
  Product = Symantec Fireglass
  Lms = Syslog
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"url_categories":""", """"original_source_ip":""", """"organization_id":"""", """"isolation_session_id":""", """"url_host":""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"time_stamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """\w+\s{1,100}\d{1,2}\s\d\d:\d\d:\d\d\s({host}[^\s]{1,2000})""",
    """"top_level_url_host":"({top_domain}[^"]{1,2000})"""",
    """"top_level_url_scheme":"({protocol}[^"]{1,2000})"""",
    """"source_ip":"({src_translated_ip}[a-fA-F\d:.]{1,2000})"""",
    """"original_source_ip":"({src_ip}[a-fA-F\d:.]{1,2000})"""",
    """"destination_ip":"({dest_ip}[a-fA-F\d:.]{1,2000})"""",
    """"source_port":({src_port}\d{1,100})""",
    """"url_port":({dest_port}\d{1,100})""",
    """"url_host":"({web_domain}[^"]{1,2000})"""",
    """"username":"(({user_email}[^@]{1,2000}@[^."]{1,2000}?\.[^"]{1,2000})|({user}[^@]{1,2000})@({domain}[^"]{1,2000}))"""",
    """"url":"({full_url}[^"]{1,2000})"""",
    """"response_status_code":({result_code}\d{1,100})""",
    """"url":"(?:-|\w+:\/+[^\/]{1,2000})({uri_path}\/[^?\s"]{1,2000})""",
    """"url":"[^"]{1,2000}?({uri_query}\?[^\s"]{1,2000})""",
    """"request_method":"({method}[^"]{1,2000})"""",
    """"user_agent":"({user_agent}[^"]{1,2000})"""",
    """"content_type":"({mime}[^"]{1,2000})"""",
    """"user_agent":"\w+\/[^"]{1,2000}?\([^"]{0,2000}?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]{1,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """"referer_url":"({referrer}[^"]{1,2000})"""",
    """"malicious":"({malicious}[^"]{1,2000})"""",
    """"total_bytes":({bytes}\d{1,100})""",
    """"action":"({action}[^"]{1,2000})""""
  ]


}
```