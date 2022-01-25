#### Parser Content
```Java
{
Name = cisco-umbrella-proxy
  Vendor = Cisco
  Product = Proxy Umbrella
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """destinationServiceName =Cisco Umbrella """, """dproc=Proxy """, """ext_url=""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\W(destinationServiceName|requestClientApplication)=({app}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsuser=(anonymous|({user}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"contentTpe"{1,20}:"{1,20}({mime}[^",]{1,2000})""",  
    """"externalIp":"{1,20}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"internalIp":"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"destinationIp"{1,20}:"{1,20}({dest_ip}[^",]{1,2000})"""",
    """"responseSize"{1,20}:"{1,20}({bytes_out}[^",]{1,2000})"""",
    """"requestSize"{1,20}:"{1,20}({bytes_in}[^",]{1,2000})"""", 
    """"statusCode"{1,20}:"{1,20}({result_code}[^",]{1,2000})"""",
    """"timestamp"{1,20}:"{1,20}({time}[^",]{1,2000})"""",
    """"referer"{1,20}:"{1,20}({referrer}[^",]{1,2000})"""",
    """"userAgent"{1,20}:"{1,20}(\s{1,100}|({user_agent}[^"]{1,2000}))"""", 
    """"url"{1,20}:"{1,20}(-|({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\\\/\s:,"]{1,2000}))?(:({dest_port}\d{1,100}))?({uri_path}\/[^\s\?"]{0,2000})?({uri_query}\?[^"\s]{0,2000})?))"""",
    """\Wext_url=\S*?({top_domain}[^\.\s:\/]{1,2000}(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch|local|tr))+)(\s|\/)""",
    """"userAgent"{1,20}:"{1,20}[^=]{0,2000}?\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]{1,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """"url"{1,20}:"{1,20}({protocol}http(s)?)""",
    """"sha"{1,20}:"{1,20}({sha}[^",]{1,2000})"""",
    """"categories"{1,20}:\["{1,20}({category}[^",]{1,2000})""",
    """"verdict"{1,20}:"{1,20}({action}[^",]{1,2000})""",
    """"identityType"{1,20}:"{1,20}({identity_type}[^",]{1,2000})""",
    """"identities"{1,20}:\["{1,20}({dest_host}[\w-]{1,2000})\.""",
    """"identities"{1,20}:\["{1,20}({user_fullname}.+?)\s{0,100}\(({user_email}({user}[^@]{1,2000})@[^\)"]{1,2000})"""
    """"categories"{1,20}:\["{1,20}({categories}[^"]{1,2000})"""", 
  ]


}
```