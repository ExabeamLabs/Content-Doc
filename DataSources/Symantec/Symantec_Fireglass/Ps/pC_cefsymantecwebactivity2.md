#### Parser Content
```Java
{
Name = cef-symantec-web-activity-2
  Vendor = Symantec
  Product = Symantec Fireglass
  Lms = QRadar
  DataType = "web-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS"
  Conditions = [ """|Symantec|Threat Isolation|""", """CEF:""", """sntdom=""", """cs4Label=URL Categories""", """sourceServiceName ="""]
  Fields = [
    """\|rt=({time}\w+\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d\.\d{1,100})""",
    """src=({src_ip}[a-fA-F\d:\.]{1,2000})""",
    """dst=({dest_ip}[a-fA-F\d:\.]{1,2000})""",
    """spt=({src_port}\d{1,100})""",
    """dpt=({dest_port}\d{1,100})""",
    """dvchost=({host}[^\s]{1,2000})""",
    """act=({action}[^=]{1,2000}?)\s\w+=""",
    """suser=({user}[^=]{1,2000}?)\s\w+=""",
    """request=({full_url}(({protocol}[^:]{1,2000}):\/\/)?({web_domain}[^\/:\s]{1,2000})({uri_path}\/[^\?\s]{0,2000})?(({uri_query}\?[^\s]{1,2000}))?)\s\w+=""",
    """requestMethod=({method}[^=]{1,2000}?)\s\w+=""",
    """dhost=({dest_host}[^\s]{1,2000})\s\w+=""",
    """sntdom=({domain}[^\s]{1,2000})""",
    """in=({bytes_out}\d{1,100})""",
    """out=({bytes_in}\d{1,100})""",
    """outcome=({outcome}[^\s]{1,2000})\s\w+=""",
    """cs4=({category}[^\s]{1,2000})\scs4Label=URL Categories""",
    """requestClientApplication=({user_agent}[^=]{1,2000})\s\w+=""",
    """requestClientApplication=[^\/=]{1,2000}?\/[^\(]{1,2000}\(({os}iOS|Android|BlackBerry|iPhone OS|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]{1,2000}?\s\w+=""",
    """requestClientApplication=[^=]{1,2000}?({browser}(?:C|c)hrome|(?:S|s)afari|(?:O|o)pera|(?:F|f)irefox|MSIE|(?:T|t)rident)[^=]{1,2000}?\s\w+=""",
    """requestContext=({referrer}[^\s]{1,2000})\s\w+=""",
    """cn2=({result_code}\d{1,100}) cn2Label=Response Status Code"""
  ]


}
```