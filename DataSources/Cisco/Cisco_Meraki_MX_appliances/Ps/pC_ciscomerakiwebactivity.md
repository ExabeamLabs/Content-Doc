#### Parser Content
```Java
{
Name = cisco-meraki-web-activity
    Vendor = Cisco
    Product = Cisco Meraki MX appliances
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch_sec"
    Conditions = [ """ urls """, """ request:""", """ src""", """ dst""" ]
    Fields = [
      """exabeam_host=({host}[^\s]{1,2000})""",
      """({time}\d{1,100})\.\d{1,100}\s{1,100}({host}[\w.\-]{1,2000})\s{1,100}urls\s""",
      """\scs6=\d{1,100}\-\d{1,100}\-\d{1,100}T\d\d:\d\d:\d\d\.\d{1,100}Z\s{1,100}({host}[a-fA-F\d.:]{1,2000})""",
      """\ssrc\\*=({src_ip}[a-fA-F\d.:]{1,2000}):({src_port}\d{1,100})""",
      """\sdst\\*=({dest_ip}[a-fA-F\d.:]{1,2000}):({dest_port}\d{1,100})""",
      """\smac\\*=({mac_address}[a-fA-F\d:]{1,2000})""",
      """\sagent\\*='?({user_agent}.+?)'?\s{0,100}request:""",
      """\sagent\\*=[^=]{0,2000}?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
      """\sagent\\*=[^=]{0,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
      """\srequest:\s{0,100}(?:UNKNOWN|({method}\w+))\s{1,100}({full_url}(\w+:\/+)?({web_domain}[^\s:\/]{1,2000})(?:\:({dest_port}\d{1,100}))?({uri_path}\/[^\?]{0,2000}?)?({uri_query}\?.+?)?)(\.\.\.)?\s{0,100}$""",
      """\srequest:\s{0,100}\S+\s{1,100}(\w+:\/+)[^\/]{0,2000}?({top_domain}[^\/\.]{1,2000}(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ad|ag|ai|am|gl|link|local|market|media|network|news|services|to|xyz))+)""",
      """\suser=CN=({user_fullname}[^=]{1,2000}?),\s{0,100}OU=""",
      """\suser=CN=({user_fullname}[^=]{1,2000}?),\s{0,100}({user_ou}OU=[^\s]{1,2000})""",
   ]
  }
```