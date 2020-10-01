#### Parser Content
```Java
{
Name = f5-silverline-waf
  Product = F5 Silverline
  Vendor = F5 Networks
  Lms = Splunk
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ type=waf""", """attack_type=""", """x_forwarded_for_header_value=""", """policy_apply_date=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s+({host}\S+)\s+""",
    """attack_type="({alert_type}[^"]+)"""",
    """dest_ip="({dest_ip}[^"]+)"""",
    """dest_port="({dest_port}[^"]+)"""",
    """ip_client="({src_ip}[^"]+)"""",
    """src_port="({src_port}[^"]+)""",
    """policy_name="({policy}[^"]+)"""",
    """protocol="({protocol}[^"]+)"""",
    """request_status="({outcome}[^"]+)"""",
    """"support_id="({alert_id}[^"]+)""",
    """severity="({alert_severity}[^"]+)"""",
    """http_class_name="({domain}[^"]+)"""",
    """support_id="({alert_id}[^"]+)"""",
    """uri="({uri_path}[^"]+)"""",
    """username="(N\/A|({user}[^"]+))"""",
    """sub_violations="(({additional_info}[^"]+))"""",
    """violations="({alert_name}[^"]+)"""
  ]
}
```