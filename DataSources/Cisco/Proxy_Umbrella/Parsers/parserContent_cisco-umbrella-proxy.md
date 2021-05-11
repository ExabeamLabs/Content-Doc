#### Parser Content
```Java
{
Name = cisco-umbrella-proxy
  Vendor = Cisco
  Product = Proxy Umbrella
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """destinationServiceName=Cisco Umbrella """, """dproc=Proxy """, """ext_url=""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\W(destinationServiceName|requestClientApplication)=({app}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsuser=(anonymous|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"contentTpe"{1,20}:"{1,20}({mime}[^",]+)""",  
    """"externalIp":"{1,20}({dest_ip}[a-fA-F\d.:]+)""",
    """"internalIp":"{1,20}({src_ip}[a-fA-F\d.:]+)""",
    """"destinationIp"{1,20}:"{1,20}({dest_ip}[^",]+)"""",
    """"responseSize"{1,20}:"{1,20}({bytes_out}[^",]+)"""",
    """"requestSize"{1,20}:"{1,20}({bytes_in}[^",]+)"""", 
    """"statusCode"{1,20}:"{1,20}({result_code}[^",]+)"""",
    """"timestamp"{1,20}:"{1,20}({time}[^",]+)"""",
    """"referer"{1,20}:"{1,20}({referrer}[^",]+)"""",
    """"userAgent"{1,20}:"{1,20}({user_agent}[^"]+)"""", 
    """"url"{1,20}:"{1,20}(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\\\/\s:,"]+))?(:({dest_port}\d{1,100}))?({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?))"""",
    """\Wext_url=\S*?({top_domain}[^\.\s:\/]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch|local|tr))+)(\s|\/)""",
    """"userAgent"{1,20}:"{1,20}[^=]*?\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """"url"{1,20}:"{1,20}({protocol}http(s)?)""",
    """"sha"{1,20}:"{1,20}({sha}[^",]+)"""",
    """"categories"{1,20}:\["{1,20}({category}[^",]+)""",
    """"verdict"{1,20}:"{1,20}({action}[^",]+)""",
    """"identityType"{1,20}:"{1,20}({identity_type}[^",]+)""",
    """"identities"{1,20}:\["{1,20}({dest_host}[\w-]+)\.""",
    """"identities"{1,20}:\["{1,20}({user_fullname}.+?)\s{0,100}\(({user_email}({user}[^@]+)@[^\)"]+)"""
    """"categories"{1,20}:\["{1,20}({categories}[^"]+)"""", 
  ]
}
```