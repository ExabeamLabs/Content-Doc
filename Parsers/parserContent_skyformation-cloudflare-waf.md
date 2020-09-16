#### Parser Content
```Java
{
Name = skyformation-cloudflare-waf
  Vendor = Cloudflare
  Product = Cloudflare
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """|Skyformation|""", """ResponseStatus"""", """FirewallMatchesActions""", """destinationServiceName=Custom Application""" ]
  Fields = [
    """"EdgeStartTimestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """({host}[\w\-.]+)\s+Skyformation""",
    """"ClientDeviceType":"({device_type}[^"]+)""",
    """"ClientCountry":"({src_country}[^"]+)""",
    """"ClientIP":"(?:["]+|({src_ip}[A-Fa-f:\d.]+))""",
    """"ClientSrcPort":({src_port}\d+)""",
    """"ClientRequestUserAgent":"({user_agent}[^"]+)""",
    """"ClientRequestBytes":({bytes_in}\d+)""",
    """"EdgeResponseBytes":({bytes_out}\d+)""",
    """"EdgeResponseStatus":({result_code}({edge_response_status}\d\d\d))"""
    """"OriginResponseStatus":({result_code}({origin_response_status}\d\d\d))"""
    """"EdgeServerIP":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"OriginIP":"({dest_ip}[A-Fa-f:\d.]+)"*.*OriginResponseBytes":({bytes_out}\d+)""",
    """"OriginIP":"(?:["]+|({dest_ip}[A-Fa-f:\d.]+))""",
    """"ClientRequestMethod":"({method}[^"]+)""",
    """"FirewallMatchesActions[":\[]+(?:["\]]+|({action}[^,"]+))""",
    """"ClientRequestHost":"({web_domain}[^"]+)""",
    """"ClientRequestURI":"({uri_query}[^"\s]+)""",
    """"ClientRequestPath":"({uri_path}[^"]+)""",
    """"ClientRequestProtocol":"({protocol}[^"]+)""",
    """"SecurityLevel":"({alert_severity}[^"]+)""",
    """"ClientRequestUserAgent[":]+.+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)(.+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))?"""
 ]
}
```