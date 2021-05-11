#### Parser Content
```Java
{
Name = cef-mcafee-epo-alert-solidifier
    Vendor = McAfee
    Product = McAfee Solidifier
    Lms = Direct
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
    Conditions = [ """Solidifier""" , """signature=""" , """category=""", """timestamp=""", """signature_id"""]
    Fields = [
      """exabeam_host=({host}[^\s]+)""",
      """\stimestamp="{0,20}({time}[^"]+)""",
      """signature="{0,20}({alert_name}[^"]+)""",
      """signature_id="{0,20}({signature_id}[^"]+)""",
      """category="{0,20}({threat_category}[^"]+)""",
      """severity_id="{0,20}({alert_severity}\d{1,100})""",
      """event_description="{0,20}({additional_info}[^"]+)""",
      """threat_type="{0,20}(?:none|({alert_type}[^"]+))""",
      """file_name="{0,20}({file_name}[^"]+)""",
      """src_ip="{0,20}({src_ip}[A-Fa-f:\d.]+)""",
      """dest_ip="{0,20}({dest_ip}[A-Fa-f:\d.]+)""",
      """\suser="{0,20}(?:N\/A|({user}[^"]+))""",
      """dest_nt_domain="{0,20}({domain}[^"]+)""",
      """os="{0,20}({os}[^"]+)""",
      """vendor_action="{0,20}(?:none|({action}[^"]+))""",
      """AutoID="{0,20}({alert_id}[^"]+)""",      
    ]
}
```