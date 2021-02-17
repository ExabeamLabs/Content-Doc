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
    """exabeam_host=([^=]+?@\s*)?({host}[\w.-]+)""",
    """http_host="(none|({host}[a-fA-F:\d\.]+):\d+|({=host}[^"]+))""",
    """\ssrc=({src_ip}[a-fA-F\d\.:]+)""",
    """\sdst=(0\.0\.0\.0|({dest_ip}[a-fA-F\d\.:]+))""",
    """src_port=({src_port}\d+)""",
    """dst_port=({dest_port}\d+)""",
    """proto=({protocol}[^\s]+)""",
    """http_agent="(none|({user_agent}[^"]+))"\s\w+=""",
    """http_method=({method}[^=]+?)\s\w+=""",
    """http_request_bytes=({bytes_out}\d+)""",
    """http_response_bytes=({bytes_in}\d+)""",
    """user_name="(Unknown|(({domain}[^\\]+)\\)?({user}[^"]+))""",
    """http_refer="(none|({referrer}[^"]+))""",
    """http_url="*(\w+:\/{2})?[^\/]+({uri_path}\/[^?\s"]+)?(\?({uri_query}[^"]+))?"""",
    """http_agent="(none|(\w+\/[^\(]+\()?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)?)""",
    """http_agent="(none|({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)[^"]+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """http_retcode=({result_code}\d+)"""
  ]
}
```