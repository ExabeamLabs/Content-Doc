#### Parser Content
```Java
{
Name = cef-forcepoint-proxy
    Vendor = Forcepoint
    Product = Websense Secure Gateway
    Lms = ArcSight
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch_sec"
    Conditions = [ "CEF","""|Forcepoint|""",""" app=""", """ request="""]
    Fields = [
      """\srt=({time}\d{10})""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """\sdvc=(-|({host}[^\s]{1,2000}))""",
      """\sdvchost=({host}[^\s]{1,2000})""",
      """\sshost=({src_host}[^\s]{1,2000})""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sspt=({src_port}\d{1,100})""",
      """\sdpt=({dest_port}\d{1,100})""",
      """\ssuser=(-|(?:\w+:\/+[\w.\-]{1,2000})\s{1,100}({user_ou}[^\/]{1,2000})\/({user_fullname}[^=]{1,2000}?))\s{1,100}\w+=""",
      """\sact=({action}[^=]{1,2000}?)\s\w+=""",
      """\srequestMethod=(?:-|({method}[^=]{1,2000}?))\s\w+=""",
      """\sin=({bytes_out}\d{1,100})""",
      """\sout=({bytes_in}\d{1,100})""",
      """\sapp=(?:-|({protocol}[^=]{1,2000}?))\s\w+=""",
      """\srequestProtocol=(?:-|({protocol}[^=]{1,2000}?))\s\w+=""",
      """\sdhost=(?:|({web_domain}[^=]{1,2000}?))\s\w+=""",
      """\srequest=({full_url}\S+)""",
      """\srequest=(?:-|(\w+:\/+[^\/]{1,2000}({uri_path}\/[^\s\?]{1,2000})({uri_query}\?[^\s]{1,2000})?))\s{1,100}\w+=""",
      """\srequestUrlFileName =(?:|({uri_path}[^=]{1,2000}?))\s\w+=""",
      """\srequestUrlQuery=(?:|({uri_query}[^=]{1,2000}?))\s\w+=""",
      """\srequestClientApplication=(?:-|({user_agent}[^=]{1,2000}?))\s{1,100}(\w+=|$)""",
      """CEF:([^\|]{1,2000}\|){4}({category}[^\|]{1,2000})\|""",
      """\scs4=({category}[^=]{1,2000}?)(\s{1,100}\w+=|;)""",
      """\scs5=({sub_category}[^=]{1,2000}?)(\s{1,100}\w+=|;)""",
      """\sflexString1=(?:User Defined[^=]{1,2000}?|({category}[^=]{1,2000}?))\s{1,100}\w+=""",
      """\sflexString2=(?:User Defined.+?|({sub_category}.+?))\s{1,100}\w+=""",
      """\scs3=(?:-|({mime}[^=]{1,2000}?))(\s{1,100}\w+=|;)""",
      """\sdhost=([^=]{0,2000}?)({top_domain}[^.\s\/:]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+\s\w+=)[^=]{1,2000}?)\s\w+=""",
      """\srequestClientApplication=(?:-|({browser}[\w\-]{1,2000}))""",
      """\srequestClientApplication=(?:-|({browser}[\w\-]{1,2000})\/[\d\._]{1,2000})""",
      """\srequestClientApplication=(?:-|({browser}[^\/]{1,2000})[^=]{1,2000}({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
      """\srequestClientApplication=(?:-|Mozilla\/[^=]{1,2000}\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]{1,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
      """\srequestClientApplication=(?:-|Mozilla\/[^=]{1,2000}\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]{1,2000}Gecko\/\d{1,100}\s{1,100}({browser}\w+))""",
      """suser=(-|({user_lastname}[^,]{1,2000}),\s({user_firstname}([A-Za-z]{1,2000}){1}(\s\w){0,1}))\s""",
      """suser=\w+:\/+([^\s]{1,2000})?\s{0,100}((CN|OU)\\+=[^,]{1,2000

}
```