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
    """({host}[\w\-.]+)\s+Skyformation """,
    """\W(destinationServiceName|requestClientApplication)=({app}.+?)(\s+\w+=|\s*$)""",
    """\Wsuser=(anonymous|({user}.+?))(\s+\w+=|\s*$)""",
    """"contentTpe"+:"+({mime}[^",]+)""",  
    """"externalIp":"+({dest_ip}[a-fA-F\d.:]+)""",
    """"internalIp":"+({src_ip}[a-fA-F\d.:]+)""",
    """"destinationIp"+:"+({dest_ip}[^",]+)"""",
    """"responseSize"+:"+({bytes_out}[^",]+)"""",
    """"requestSize"+:"+({bytes_in}[^",]+)"""", 
    """"statusCode"+:"+({result_code}[^",]+)"""",
    """"timestamp"+:"+({time}[^",]+)"""",
    """"referer"+:"+({referrer}[^",]+)"""",
    """"userAgent"+:"+({user_agent}[^"]+)"""", 
    """"url"+:"+(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\\\/\s:,"]+))?(:({dest_port}\d+))?({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?))"""",
    """\Wext_url=\S*?({top_domain}[^\.\s:\/]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch|local|tr))+)(\s|\/)""",
    """"userAgent"+:"+[^=]*?\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """"url"+:"+({protocol}http(s)?)""",
    """"sha"+:"+({sha}[^",]+)"""",
    """"categories"+:\["+({category}[^",]+)""",
    """"verdict"+:"+({action}[^",]+)""",
    """"identityType"+:"+({identity_type}[^",]+)""",
    """"identities"+:\["+({dest_host}[\w-]+)\.""",
    """"identities"+:\["+({user_fullname}.+?)\s*\(({user_email}({user}[^@]+)@[^\)"]+)"""
  ]
}
```