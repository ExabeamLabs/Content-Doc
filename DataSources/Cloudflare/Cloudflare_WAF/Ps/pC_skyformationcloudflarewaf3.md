#### Parser Content
```Java
{
Name = skyformation-cloudflare-waf-3
  Vendor = Cloudflare
  Product = Cloudflare WAF
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """destinationServiceName =Cloudflare""", """ResponseStatus"""", """SecurityActions""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"EdgeStartTimestamp"{1,20}:"{0,20}({time}\d{1,2000})""",
    """"EdgeStartTimestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """"ClientDeviceType"{1,20}:"{1,20}({device_type}[^"]{1,2000})""",
    """"ClientCountry"{1,20}:"{1,20}({src_country}[^"]{1,2000})""",
    """"ClientIP"{1,20}:"{1,20}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"ClientSrcPort"{1,20}:({src_port}\d{1,100})""",
    """"ClientRequestUserAgent"{1,20}:"{1,20}({user_agent}[^"]{1,2000})""",
    """"ClientRequestBytes"{1,20}:({bytes_in}\d{1,100})""",
    """"EdgeResponseBytes"{1,20}:({bytes_out}\d{1,100})""",
    """"EdgeResponseStatus"{1,20}:({result_code}({edge_response_status}\d\d\d))"""
    """"OriginResponseStatus"{1,20}:({result_code}({origin_response_status}\d\d\d))"""
    """"EdgeServerIP"{1,20}:"{1,20}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"OriginIP"{1,20}:"{1,20}({dest_ip}[A-Fa-f:\d.]{1,2000})"{0,20}.*OriginResponseBytes"{1,20}:({bytes_out}\d{1,100})""",
    """"OriginIP"{1,20}:"{1,20}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"ClientRequestMethod"{1,20}:"{1,20}({method}[^"]{1,2000})""",
    """"SecurityActions[":\[]{1,2000}(?:["\]]{1,2000}|({action}[^,"]{1,2000}))""",
    """"ClientRequestHost"{1,20}:"{1,20}({web_domain}[^"]{1,2000})""",
    """"ClientRequestURI"{1,20}:"{1,20}({uri_query}[^"\s]{1,2000})""",
    """"ClientRequestPath"{1,20}:"{1,20}({uri_path}[^"]{1,2000})""",
    """"ClientRequestProtocol"{1,20}:"{1,20}({protocol}[^"]{1,2000})""",
    """"SecurityLevel"{1,20}:"{1,20}({alert_severity}[^"]{1,2000})"""
  ]
  DupFields = [ "dest_ip->host" ]


}
```