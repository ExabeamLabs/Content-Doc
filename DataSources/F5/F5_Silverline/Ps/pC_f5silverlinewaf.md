#### Parser Content
```Java
{
Name = f5-silverline-waf
  Product = F5 Silverline
  Vendor = F5
  Lms = Splunk
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ type=waf""", """attack_type=""", """x_forwarded_for_header_value=""", """policy_apply_date=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s{1,100}({host}\S+)\s{1,100}""",
    """attack_type="({alert_type}[^"]{1,2000})"""",
    """dest_ip="({dest_ip}[^"]{1,2000})"""",
    """dest_port="({dest_port}[^"]{1,2000})"""",
    """ip_client="({src_ip}[^"]{1,2000})"""",
    """src_port="({src_port}[^"]{1,2000})""",
    """policy_name="({policy}[^"]{1,2000})"""",
    """protocol="({protocol}[^"]{1,2000})"""",
    """request_status="({outcome}[^"]{1,2000})"""",
    """"support_id="({alert_id}[^"]{1,2000})""",
    """severity="({alert_severity}[^"]{1,2000})"""",
    """http_class_name="({domain}[^"]{1,2000})"""",
    """support_id="({alert_id}[^"]{1,2000})"""",
    """uri="({uri_path}[^"]{1,2000})"""",
    """username="(N\/A|({user}[^"]{1,2000}))"""",
    """sub_violations="(({additional_info}[^"]{1,2000}))"""",
    """violations="({alert_name}[^"]{1,2000})"""
  ]
}
```