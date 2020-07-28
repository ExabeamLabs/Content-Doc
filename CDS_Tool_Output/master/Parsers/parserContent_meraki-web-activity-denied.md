#### Parser Content
```Java
{
Name = meraki-web-activity-denied
  Vendor = Cisco
  Product = Cisco Meraki MX appliances
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """ events content_filtering_block """, """ url=""" ]
  Fields = [
    """({host}[\w.\-]+) ({time}\d+)\.\d+\s+\S+\s+events content_filtering_block""",
    """\scategory0='({category}[^']+)""",
    """\sserver='({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({dest_port}\d+)""",
    """\surl='({full_url}(({protocol}\w+):\/+)?({web_domain}[^\/']+)({uri_path}[^\?']+?)?({uri_query}\?.+?)?)'""",
    """\surl='(\w+:\/+)[^\/']*?({top_domain}[^\/\.']+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|tech))+)(\/|')""",
  ]
}
```