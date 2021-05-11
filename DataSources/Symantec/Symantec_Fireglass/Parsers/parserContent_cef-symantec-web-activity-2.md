#### Parser Content
```Java
{
Name = cef-symantec-web-activity-2
  Vendor = Symantec
  Product = Symantec Fireglass
  Lms = QRadar
  DataType = "web-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS"
  Conditions = [ """|Symantec|Threat Isolation|""", """CEF:""", """sntdom=""", """cs4Label=URL Categories""", """sourceServiceName="""]
  Fields = [
    """\|rt=({time}\w+\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d\.\d{1,100})""",
    """src=({src_ip}[a-fA-F\d:\.]+)""",
    """dst=({dest_ip}[a-fA-F\d:\.]+)""",
    """spt=({src_port}\d{1,100})""",
    """dpt=({dest_port}\d{1,100})""",
    """dvchost=({host}[^\s]+)""",
    """act=({action}[^=]+?)\s\w+=""",
    """suser=({user}[^=]+?)\s\w+=""",
    """request=({full_url}(({protocol}[^:]+):\/\/)?({web_domain}[^\/:\s]+)({uri_path}\/[^\?\s]*)?(({uri_query}\?[^\s]+))?)\s\w+=""",
    """requestMethod=({method}[^=]+?)\s\w+=""",
    """dhost=({dest_host}[^\s]+)\s\w+=""",
    """sntdom=({domain}[^\s]+)""",
    """in=({bytes_out}\d{1,100})""",
    """out=({bytes_in}\d{1,100})""",
    """outcome=({outcome}[^\s]+)\s\w+=""",
    """cs4=({category}[^\s]+)\scs4Label=URL Categories""",
    """requestClientApplication=({user_agent}[^=]+)\s\w+=""",
    """requestClientApplication=[^\/=]+?\/[^\(]+\(({os}iOS|Android|BlackBerry|iPhone OS|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]+?\s\w+=""",
    """requestClientApplication=[^=]+?({browser}(?:C|c)hrome|(?:S|s)afari|(?:O|o)pera|(?:F|f)irefox|MSIE|(?:T|t)rident)[^=]+?\s\w+=""",
    """requestContext=({referrer}[^\s]+)\s\w+=""",
    """cn2=({result_code}\d{1,100}) cn2Label=Response Status Code"""
  ]
}
```