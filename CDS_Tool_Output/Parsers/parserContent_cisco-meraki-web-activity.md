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
      """exabeam_host=({host}[^\s]+)""",
      """({time}\d+)\.\d+\s+({host}[\w.\-]+)\s+urls\s""",
      """\scs6=\d+\-\d+\-\d+T\d\d:\d\d:\d\d\.\d+Z\s+({host}[a-fA-F\d.:]+)""",
      """\ssrc\\*=({src_ip}[a-fA-F\d.:]+):({src_port}\d+)""",
      """\sdst\\*=({dest_ip}[a-fA-F\d.:]+):({dest_port}\d+)""",
      """\smac\\*=({mac_address}[a-fA-F\d:]+)""",
      """\sagent\\*='?({user_agent}.+?)'?\s*request:""",
      """\sagent\\*=[^=]*?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
      """\sagent\\*=[^=]*?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
      """\srequest:\s*(?:UNKNOWN|({method}\w+))\s+({full_url}(\w+:\/+)?({web_domain}[^\s:\/]+)(?:\:({dest_port}\d+))?({uri_path}\/[^\?]*?)?({uri_query}\?.+?)?)(\.\.\.)?\s*$""",
      """\srequest:\s*\S+\s+(\w+:\/+)[^\/]*?({top_domain}[^\/\.]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ad|ag|ai|am|gl|link|local|market|media|network|news|services|to|xyz))+)""",
      """\suser=CN=({user_fullname}[^=]+?),\s*OU=""",
      """\suser=CN=({user_fullname}[^=]+?),\s*({user_ou}OU=[^\s]+)""",
   ]
  }
```