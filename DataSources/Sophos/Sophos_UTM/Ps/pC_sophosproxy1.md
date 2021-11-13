#### Parser Content
```Java
{
Name = sophos-proxy-1
  Vendor = Sophos
  Product = Sophos UTM
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy:MM:dd-HH:mm:ss"
  Conditions = [ """ name="http access"""", """ fullreqtime="""" ]
  Fields = [
	"""({time}\d\d\d\d:\d\d:\d\d-\d\d:\d\d:\d\d)\s{1,100}({host}[\w\-.]{1,2000})""",
    """sub="(|({protocol}[^"]{1,2000}))"""",
    """action="(|({action}[^"]{1,2000}))"""",
    """method="(|({method}[^"]{1,2000}))"""",
    """srcip="(|({src_ip}[^"]{1,2000}))"""",
    """dstip="(|({dest_ip}[^"]{1,2000}))"""",
    """user="(|({user}[^"]{1,2000}))"""",
    """statuscode="(|({result_code}[^"]{1,2000}))"""",
    """url="({full_url}[^"]{1,2000})""",
    """url="(?:-|({protocol}[^:]{1,2000}))""",
    """url="(?:-|\w+:\/+[^\/]{1,2000})({uri_path}\/[^?\s"]{1,2000})""",
    """url="(?:-|(?=(?)(?:[^?]{1,2000}({uri_query}\?[^\s"]{1,2000}))))""",
    """url="(?:[^:]{1,2000}:\/+)({web_domain}[^\/:\s]{1,2000})""",
    """referer="(|({referrer}[^"]{1,2000}))"""",
    """ua="(|({user_agent}[^"]{1,2000}))"""",
    """category="({category}[^"]{1,2000})""",
    """content-type="({mime}[^"]{1,2000})""", 
  ]


}
```