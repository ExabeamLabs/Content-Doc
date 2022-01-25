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
  Conditions = [ """|Skyformation|""", """destinationServiceName =Cloudflare""", """"ClientIP":"""", """"FirewallMatchesActions":""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s{1,100}[^\s]{1,2000}\s{1,100}Skyformation""",
    """"ClientRequestHost":"({host}[^"]{1,2000})""",
    """"RayID":"({alert_id}[^"]{1,2000})""",
    """"WAFAction":"(unknown|({proxy_action}[^"]{1,2000}))""",
    """"WAFRuleID":"({event_code}[^"]{1,2000})""",
    """"WAFRuleMessage":"({additional_info}[^"]{1,2000})""",
    """dhost=({dest_host}[^\s]{1,2000})""",
    """suser=(anonymous|({user}[^\s]{1,2000}))""",
    """"ClientDeviceType":"({device_type}[^"]{1,2000})""",
    """"ClientCountry":"({src_country}[^"]{1,2000})""",
    """"ClientIP":"(?:["]{1,2000}|({src_ip}[A-Fa-f:\d.]{1,2000}))""",
    """"ClientSrcPort":({src_port}\d{1,100})""",
    """"ClientRequestUserAgent":"({user_agent}[^"]{1,2000})""",
    """"ClientRequestBytes":({bytes_in}\d{1,100})""",
    """"EdgeResponseBytes":({bytes_out}\d{1,100})""",
    """"EdgeResponseStatus":({result_code}({edge_response_status}\d\d\d))"""
    """"OriginResponseStatus":({result_code}({origin_response_status}\d\d\d))"""
    """"EdgeServerIP":"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"OriginIP":"({dest_ip}[A-Fa-f:\d.]{1,2000})"{0,20}[^=]{1,2000}?OriginResponseBytes":({bytes_out}\d{1,100})""",
    """"OriginIP":"(?:["]{1,2000}|({dest_ip}[A-Fa-f:\d.]{1,2000}))""",
    """"ClientRequestMethod":"(UNKNOWN|({method}[^"]{1,2000}))""",
    """"FirewallMatchesActions[":\[]{1,2000}(?:["\]]{1,2000}|({action}[^,"]{1,2000}))""",
    """\|act=({action}[^\s]{1,2000})\s\w+=""",
    """"ClientRequestHost":"({web_domain}[^"]{1,2000})""",
    """"clientRequestHTTPHost"{1,20}:"{1,20}[^\s"?=]{0,2000}?({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)(?::\d{1,100})?)+(?:\s\w+=|\/|))[^"\s:\/]{1,2000})""",
    """"ClientRequestURI":"({uri_path}[^"\?\s]{1,2000})(?:\?({uri_query}[^?\s"]{1,2000}))?""",
    """"ClientRequestProtocol":"({protocol}[^"]{1,2000})""",
    """"SecurityLevel":"({alert_severity}[^"]{1,2000})""",
    """"ClientRequestReferer":"({referrer}[^"]{1,2000}?)",""",
    """"ClientRequestUserAgent[":]{1,2000}[^=]{1,2000}?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)([^=]{1,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))?"""
    ]


}
```