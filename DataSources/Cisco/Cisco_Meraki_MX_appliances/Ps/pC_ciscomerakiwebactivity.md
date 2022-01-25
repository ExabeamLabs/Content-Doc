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
      """\srequest:\s{0,100}(?:UNKNOWN|({method}\w+))\s{1,100}({full_url}(\w+:\/+)?({web_domain}[^\s:\/]{1,2000})(?:\:({dest_port}\d{1,100}))?({uri_path}\/[^\?"]{0,2000}?)?({uri_query}\?.+?)?)(\.\.\.)?\s{0,100}($|")""",
   ]
  

}
```