#### Parser Content
```Java
{
Name = s-mcafee-epo-dlp-alert-2
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
    Conditions = [ """timestamp=""", """signature_id""", """is_laptop""", """Data Loss Prevention""" ]
    Fields = [
      """timestamp="{0,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """AutoID="{0,20}({alert_id}\d{1,100})""",
      """signature="{0,20}\s{0,100}(_|({alert_name}.+?))\s{0,100}"{0,20},? threat_type""", 
      """threat_type="{0,20}(\s|none|({alert_type}.+?))"{0,20},? signature_id""",
      """signature_id="{0,20}({signature_id}\d{1,100})""",
      """severity_id="{0,20}({alert_severity}\d{1,100})""",
      """event_description="{0,20}({additional_info}[^"]{1,2000})""",
      """\Wprocess="{0,20}({process}({directory}(?:(\w+:)?[^:"]{1,2000})?[\\\/])?({process_name}[^\\"]{1,2000}))""",
      """\slogon_user.+?user="{0,20}(N\/A|\s{1,100}|NULL|([^\\]{1,2000}\\+)?({user}[^\s,"]{1,2000}))""",
      """, username="{1,20}(N\/A|NULL|({user}[^,]{1,2000}?))(|,.*?)"{1,20},""",
      """src_dns="{0,20}({src_host}[^\s"]{1,2000})"""",
      """src_ip="({src_ip}[A-Fa-f:\d.]{1,2000})"""",
      """dest_dns="{0,20}({dest_host}[^\s"]{1,2000})"""",
      """dest_ip="{0,20}({dest_ip}[A-Fa-f:\d.]{1,2000})"""",
      """os="{0,20}({os}[^"]{1,2000})"""",
      """category="{0,20}({category}[^\s"]{1,2000})"""",
    ]
  DupFields = [ "directory->process_directory" ]
}
```