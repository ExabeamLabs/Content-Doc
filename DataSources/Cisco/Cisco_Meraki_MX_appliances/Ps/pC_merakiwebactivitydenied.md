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
    """({host}[\w.\-]{1,2000}) ({time}\d{1,100})\.\d{1,100}\s{1,100}\S+\s{1,100}events content_filtering_block""",
    """\scategory0='({category}[^']{1,2000})""",
    """\sserver='({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({dest_port}\d{1,100})""",
    """\surl='({full_url}(({protocol}\w+):\/+)?({web_domain}[^\/']{1,2000})({uri_path}[^\?']{1,2000}?)?({uri_query}\?.+?)?)'""",
  ]


}
```