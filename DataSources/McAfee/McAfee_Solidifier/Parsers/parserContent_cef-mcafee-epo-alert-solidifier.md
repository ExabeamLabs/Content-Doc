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
      """\stimestamp="*({time}[^"]+)""",
      """signature="*({alert_name}[^"]+)""",
      """signature_id="*({signature_id}[^"]+)""",
      """category="*({threat_category}[^"]+)""",
      """severity_id="*({alert_severity}\d+)""",
      """event_description="*({additional_info}[^"]+)""",
      """threat_type="*(?:none|({alert_type}[^"]+))""",
      """file_name="*({file_name}[^"]+)""",
      """src_ip="*({src_ip}[A-Fa-f:\d.]+)""",
      """dest_ip="*({dest_ip}[A-Fa-f:\d.]+)""",
      """\suser="*(?:N\/A|({user}[^"]+))""",
      """dest_nt_domain="*({domain}[^"]+)""",
      """os="*({os}[^"]+)""",
      """vendor_action="*(?:none|({action}[^"]+))""",
      """AutoID="*({alert_id}[^"]+)""",      
    ]
}
```