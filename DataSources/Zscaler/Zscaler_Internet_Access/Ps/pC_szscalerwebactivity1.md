#### Parser Content
```Java
{
Name = s-zscaler-web-activity-1
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ ""","ologin":"""", ""","cip":"""", ""","url":"""", ""","urlsupercat":"""", ""","reqdatasize":""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"time":"({time}\d\d\d\d-\d\d-\d\d \d{1,100}:\d{1,100}:\d{1,100})""",
    """"ologin":"({user_email}({user}[^@\s"]{1,2000})@[^@\s"]{1,2000})"""",
    """"cip":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"proto":"({protocol}[^"]{1,2000})""",
    """"reqmethod":"({method}[^"]{1,2000})""",
    """"url":"({full_url}[^"]{1,2000})""",
    """"url":"(?:[^:]{1,2000}:\/+)?({web_domain}[^\/:\s"]{1,2000})({uri_path}\/[^\?"]{1,2000})?({uri_query}\?[^"]{1,2000})?""",
    """"respcode":"({result_code}[^"]{1,2000})""",
    """"sip":"({dest_ip}[^"]{1,2000})""",
    """"action":"({action}[^"]{1,2000})""",
    """"reason":"({proxy_action}[^"]{1,2000})""",
    """"urlsupercat":"({category}[^"]{1,2000})""",
    """"ua":"({user_agent}[^"]{1,2000})""",
    """"referer":"({referrer}[^"]{1,2000})""",
    """"fileclass":"({mime}[^"]{1,2000})""",
    """"reqdatasize":({bytes_out}\d{1,100})""",
    """"respdatasize":({bytes_in}\d{1,100})""",
  ]


}
```