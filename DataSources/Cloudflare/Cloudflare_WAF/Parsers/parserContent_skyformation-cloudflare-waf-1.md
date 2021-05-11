#### Parser Content
```Java
{
Name = skyformation-cloudflare-waf-1
  Vendor = Cloudflare
  Product = Cloudflare WAF
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|Skyformation|""", """destinationServiceName=Cloudflare""", """"ClientIP":"""", """"FirewallMatchesActions":""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s{1,100}[^\s]+\s{1,100}Skyformation""",
    """"ClientRequestHost":"({host}[^"]+)""",
    """"RayID":"({alert_id}[^"]+)""",
    """"WAFAction":"(unknown|({proxy_action}[^"]+))""",
    """"WAFRuleID":"({event_code}[^"]+)""",
    """"WAFRuleMessage":"({additional_info}[^"]+)""",
    """dhost=({dest_host}[^\s]+)""",
    """suser=(anonymous|({user}[^\s]+))""",
    """"ClientDeviceType":"({device_type}[^"]+)""",
    """"ClientCountry":"({src_country}[^"]+)""",
    """"ClientIP":"(?:["]+|({src_ip}[A-Fa-f:\d.]+))""",
    """"ClientSrcPort":({src_port}\d{1,100})""",
    """"ClientRequestUserAgent":"({user_agent}[^"]+)""",
    """"ClientRequestBytes":({bytes_in}\d{1,100})""",
    """"EdgeResponseBytes":({bytes_out}\d{1,100})""",
    """"EdgeResponseStatus":({result_code}({edge_response_status}\d\d\d))"""
    """"OriginResponseStatus":({result_code}({origin_response_status}\d\d\d))"""
    """"EdgeServerIP":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"OriginIP":"({dest_ip}[A-Fa-f:\d.]+)"{0,20}[^=]+?OriginResponseBytes":({bytes_out}\d{1,100})""",
    """"OriginIP":"(?:["]+|({dest_ip}[A-Fa-f:\d.]+))""",
    """"ClientRequestMethod":"(UNKNOWN|({method}[^"]+))""",
    """"FirewallMatchesActions[":\[]+(?:["\]]+|({action}[^,"]+))""",
    """\|act=({action}[^\s]+)\s\w+=""",
    """"ClientRequestHost":"({web_domain}[^"]+)""",
    """"clientRequestHTTPHost"{1,20}:"{1,20}[^\s"?=]*?({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)(?::\d{1,100})?)+(?:\s\w+=|\/|))[^"\s:\/]+)""",
    """"ClientRequestURI":"({uri_path}[^"\?\s]+)(?:\?({uri_query}[^?\s"]+))?""",
    """"ClientRequestProtocol":"({protocol}[^"]+)""",
    """"SecurityLevel":"({alert_severity}[^"]+)""",
    """"ClientRequestReferer":"({referrer}[^"]+?)",""",
    """"ClientRequestUserAgent[":]+[^=]+?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)([^=]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))?"""
    ]
}
```