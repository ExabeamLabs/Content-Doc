#### Parser Content
```Java
{
Name = s-mcafee-epo-alert-4
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """signature_id="""", """threat_handled="""", """threat_type="""", """detection_method="""", """product="McAfee Endpoint Security"""" ]
    Fields = [
      """detected_timestamp="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """signature="(_|\s{1,200}|({alert_name}[^"]{1,2000}))"""",
      """signature_id="({signature_id}[^"]{1,2000})"""",
      """category="({threat_category}[^"]{1,2000})"""",
      """fqdn="({host}[\w\-.]{1,2000})"""",
      """severity_id="({alert_severity}\d{1,100})"""",
      """src_ip="({src_ip}[A-Fa-f0-9.:]{1,2000})"""",
      """dest_ip="({dest_ip}[A-Fa-f0-9.:]{1,2000})"""",
      """threat_type="(\s{1,200}|({alert_type}[^"]{1,2000}))"""",
      """dest_nt_domain="({domain}[^"]{1,2000})"""",
      """user="{0,20}(N\/A|\s{1,100}|NULL|([^\\]{1,2000}\\+)?({user}[^\s,"]{1,2000}))"""",
      """AutoID="({alert_id}[^"]{1,2000})""""
    ]
 

}
```