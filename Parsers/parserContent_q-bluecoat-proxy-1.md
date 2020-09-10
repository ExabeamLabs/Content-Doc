#### Parser Content
```Java
{
Name = q-bluecoat-proxy-1
  Vendor = Symantec
  Product = Blue Coat ProxySG Appliance
  Lms = QRadar
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss"
  Conditions = [ """ OBSERVED """, """ TCP_""", """http""", """]"""" ]
  Fields = [
    """"\[({time}\d\d/\w+/\d\d\d\d:\d\d:\d\d:\d\d)\s*[+-]\d+\]"""",
    """[+-]\d+\]"\s+\S+\s+(?:-|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w.\-]+))\s+(?:-|(({domain}[^\s\\]*?)\\)?({user}[^\s\\]+))+\s+"(?:none|({category}[^"]*?))"\s+(?:-|({result_code}\d+))\s+(?:-|({proxy_action}\S+))\s+(?:-|({bytes_out}\d+))\s+(?:-|({bytes_in}\d+))\s+(?:-|({method}\S+))\s+(?:-|({protocol}\S+))\s+(?:-|({web_domain}[^\s]+))\s+(?:-|({dest_port}\d+))\s+(?:-|({uri_path}\S+))\s+(\S+\s+){3}(?:-|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[\w.\-]+)\s+(?:|-|({mime}\S+))\s+"({user_agent}.*?)"\s+({action}\S+)\s+""",
    """\shttp\s+[^\s]*?({top_domain}[^\s.]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|tech|vn|goog|ai))+)\s+""",
    """"Mozilla\/.+\(.*?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)[^"]*?"\s+(OBSERVED|PROXIED|DENIED)"""
  ]
}
```