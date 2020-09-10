#### Parser Content
```Java
{
Name = checkpoint-network-decrypt
  DataType = "network-alert"
  Conditions = [ """CheckPoint""", """product:"""", """action:"accept decrypt"""" ]
  Fields = ${CheckpointParserTemplates.checkpoint-auth.Fields}[
    """event_name:"+({alert_name}[^"]+)""",
    """cu_rule_category:"+({alert_type}[^"]+)""",
    """proto:"+({protocol}[^"]+)""",
    """cu_rule_id:"+({rule_id}[^"]+)""",
    """service:"+({service}\d+)"""
    """cu_action:"+({action}[^"]+)""",
    """cu_detected_by:"+({src_ip}[^"]+)""",
    """ src:"+({src_ip}[A-Fa-f:\d.]+)""",
    """dst:"+({dest_ip}[^"]+)""",
    """\Wproduct:"({product_name}[^"]+)\s*""",
  ]
}


{
  Name = checkpoint-web-activity
  Vendor = Check Point
  Product = Check Point NGFW
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """CheckPoint""", """product:"URL Filtering"""", """ifname:"""" ]
  Fields = [
    """\Wtime:"({time}\d+)""",
    """\W({host}[\w\-.]+) CheckPoint""",
    """\Wuser:"({user_lastname}[^,]+),\s*({user_firstname}[\w\s]+\S)\s*\(({account}.+?)\)""",
    """\Wsrc:"({src_ip}[A-Fa-f:\d.]+)""",
    """\Wdst:"({dest_ip}[A-Fa-f:\d.]+)""",
    """\Waction:"({action}[^"]+)""",
    """\Ws_port:"({src_port}\d+)""",
    """\Wproto:"({protocol}[^"]+)""",
    """\Wservice:"({dest_port}\d+)""",
    """\Wmatched_category:"({category}[^"]+)""",
    """\Wappi_name:"\s*({web_domain}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^;\/"]+)""",
    """\Wresource:"\s*(-|({full_url}[^"]+))""",
    """\Wresource:"\s*(?:-|({protocol}[^:]+))""",
    """\Wresource:"\s*(?:-|(\w+:\/+[^\/]+\/({uri_path}[^?;"]+)))""",
    """\Wresource:"\s*(?:-|(\w+:\/+[^?]+({uri_query}\?[^;"]+?)))"""",
    """\Wweb_client_type:"(Other:)?\s*(?:-|({user_agent}[^"]+))""",
    """\Wweb_client_type:"(Other:)?\s*(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """\Wappi_name:"(.*?)({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(;|\/))[^;\/]+)""",
    """\Worigin:"({origin_ip}[^"]+)""",
    """\Worigin_sic_name:"CN=({origin_name}[^",]+)""",
    """\Wproduct:"({product_name}[^"]+)""",
    """\Wsrc_machine_name:"({src_host}[^"@]+)@({domain}[^"]+)""",
    """\Wuser:"({user}[^"]+?)\s*"""",
  ]
}
```