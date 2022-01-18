#### Parser Content
```Java
{
Name = leef-incapsula-web-activity
  Vendor = Imperva
  Product = Incapsula
  Lms = Direct 
  DataType = "web-activity"
  TimeFormat = "epoch"
  Conditions = [ """LEEF:""", """|Incapsula|SIEMintegration|""", """deviceExternalId=""","""fileId=""" ]
  Fields = [
    """\d:\d\d:\d\d\.\d{1,100}Z\s({host}[^\s]{1,2000})""",
    """\Wstart=({time}\d{1,100})"""  
    """siteid=({site_id}\d{1,100})""",
    """requestMethod=({method}[^\s]{1,2000})""",
    """\WsourceServiceName =({web_domain}([^\s]{1,2000}\.)?({top_domain}[^\s]{1,2000}\.[^\s]{1,2000})?)\s""",
    """\WrequestClientApplication=({user_agent}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\WrequestClientApplication=[^=]{0,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\WrequestClientApplication=[^=]{0,2000}?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """ref=({referrer}[^\s]{1,2000})""",
    """proto=({protocol}[^\s]{1,2000})""",
    """srcPort=({src_port}\d{1,100})""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdproc=({category}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """calCountryOrRegion=({country_code}[^\s]{1,2000})""",
    """\Wurl=(-|({full_url}(({protocol}[^:\\\/\s]{1,2000}):[\\\/]{1,2000})?({web_domain}[^\\\/\s:]{1,2000})(:\d{1,100})?(\/|({uri_path}\/[^\?"]{0,2000}?))?({uri_query}\?[^"\s]{0,2000}?)?))\s{1,100}(\w+=|$)""",
    """\WsourceServiceName =[^\s\=]{0,2000}?({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\s|\/|$))[^\s\/]{1,2000})\s{1,100}(\w+=|$)""",
    """cat=({action}[^\s]{1,2000})""",
    """dstPort=({dest_port}\d{1,100})""",
    """dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """cs9=(,)?(,|\s{1,100}|({alert_name}[^=]{1,2000}?))\s{0,100}(,|\w+=|$)""",
    """LEEF[^|]{1,2000}\|([^|]{0,2000}\|){3}({categories}[^|]{1,2000})""",
    """cs6=({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """fileId=({alert_id}\d{1,100})""",
    """cn1=({result_code}\d{1,100})""",
    """qstr=({uri_query}[^\s]{1,2000})""",
   ]


}
```