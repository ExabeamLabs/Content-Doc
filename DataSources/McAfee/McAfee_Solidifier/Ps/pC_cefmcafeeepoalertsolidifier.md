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
      """exabeam_host=({host}[^\s]{1,2000})""",
      """\stimestamp="{0,20}({time}[^"]{1,2000})""",
      """signature="{0,20}({alert_name}[^"]{1,2000})""",
      """signature_id="{0,20}({signature_id}[^"]{1,2000})""",
      """category="{0,20}({threat_category}[^"]{1,2000})""",
      """severity_id="{0,20}({alert_severity}\d{1,100})""",
      """event_description="{0,20}({additional_info}[^"]{1,2000})""",
      """threat_type="{0,20}(?:none|({alert_type}[^"]{1,2000}))""",
      """file_name="{0,20}({file_name}[^"]{1,2000})""",
      """src_ip="{0,20}({src_ip}[A-Fa-f:\d.]{1,2000})""",
      """dest_ip="{0,20}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
      """\suser="{0,20}(?:N\/A|({user}[^"]{1,2000}))""",
      """dest_nt_domain="{0,20}({domain}[^"]{1,2000})""",
      """os="{0,20}({os}[^"]{1,2000})""",
      """vendor_action="{0,20}(?:none|({action}[^"]{1,2000}))""",
      """AutoID="{0,20}({alert_id}[^"]{1,2000})""",      
    ]
}
```