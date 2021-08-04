#### Parser Content
```Java
{
Name = websense-proxy-2
  Vendor = Forcepoint
  Product = Websense Secure Gateway
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """category=""", """bytes_out=""", """bytes_in=""", """http_method="""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}(\w+=|$)""",
    """\Wcategory="?({category}.+?)"?,?\s{0,100}(\w+=|$)""",
    """\Wsrc_host="?({src_host}.+?)"?,?\s{0,100}(\w+=|$)""",
    """\Wsrc_host="?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wde?st="?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Whost_masked="?({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdest_ip_masked="?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdst_ip="?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wbytes_out="?({bytes_in}\d{1,100})""",
    """\Wbytes_in="?({bytes_out}\d{1,100})""",
    """\Whttp_method="?({method}.+?)"?,?\s{0,100}(\w+=|$)""",
    """\Wstatus="?({result_code}\d{1,100})""",
    """\Whttp_proxy_status_code="?({result_code}\d{1,100})""",
    """\Whttp_server_status_code="?({result_code}\d{1,100})""",
    """\Wdisposition="?({action}.+?)"?,?\s{0,100}(\w+=|$)""",
    """\Waction="?(?:-|({action}.+?))"?,?\s{0,100}(\w+=|$)""",
    """\Wurl="?({full_url}.+?)"?,?\s{1,100}(\w+=|$)""",
    """\Wurl="?(?:-|({protocol}\w+))\\*:\/+""",
    """\Wurl="?(?:-|(\w+\\*:\/+)?[^\/"=]{1,2000})({uri_path}\/[^\/][^?\s"]{0,2000})""",
    """\Wurl="?[^\?\s"=]{0,2000}({uri_query}\?[^\s"]{0,2000})"?,?(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wurl="?(?:[^:]{1,2000}\\*:\/+)?({web_domain}[^\/:\s"]{1,2000})""",
    """\Wurl="?(\w+\\*:\/+)?([^\/]{0,2000}?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:"]{1,2000}(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|br))+)(\s|\/|$|:|")""",
    """\Wcache="{0,20}({proxy_action}.+?)"{0,20}
```