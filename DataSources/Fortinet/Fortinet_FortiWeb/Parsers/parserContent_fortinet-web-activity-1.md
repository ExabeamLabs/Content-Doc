#### Parser Content
```Java
{
Name = fortinet-web-activity-1
  Vendor = Fortinet
  Product = Fortinet FortiWeb
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd' time='HH:mm:ss"
  Conditions = [ """proto=tcp""", """type=traffic""", """original_src=""", """content_switch_name=""", """service=""", """user_name="""", """http_url="""", """pri=""", """http_method=""" ]
  Fields = [
    """\Wdate=({time}\d\d\d\d-\d\d-\d\d time\=\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """http_host="(none|({host}[a-fA-F:\d\.]{1,2000}):\d{1,100}|({=host}[^"]{1,2000}))""",
    """\ssrc=({src_ip}[a-fA-F\d\.:]{1,2000})""",
    """\sdst=(0\.0\.0\.0|({dest_ip}[a-fA-F\d\.:]{1,2000}))""",
    """src_port=({src_port}\d{1,100})""",
    """dst_port=({dest_port}\d{1,100})""",
    """proto=({protocol}[^\s]{1,2000})""",
    """http_agent="(none|({user_agent}[^"]{1,2000}))"\s\w+=""",
    """http_method=({method}[^=]{1,2000}?)\s\w+=""",
    """http_request_bytes=({bytes_out}\d{1,100})""",
    """http_response_bytes=({bytes_in}\d{1,100})""",
    """user_name="(Unknown|(({domain}[^\\]{1,2000})\\)?({user}[^"]{1,2000}))""",
    """http_refer="(none|({referrer}[^"]{1,2000}))""",
    """http_url="{0,20}(\w+:\/{2})?[^\/]{1,2000}({uri_path}\/[^?\s"]{1,2000})?(\?({uri_query}[^"]{1,2000}))?"""",
    """http_agent="(none|(\w+\/[^\(]{1,2000}\()?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]{1,2000}({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)?)""",
    """http_agent="(none|({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)[^"]{1,2000}({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """http_retcode=({result_code}\d{1,100})"""
  ]
}
```