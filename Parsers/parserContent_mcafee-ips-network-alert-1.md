#### Parser Content
```Java
{
Name = mcafee-ips-network-alert-1
  Vendor = McAfee
  Product = McAfee Network Security Platform (IPS)
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss z"
  Conditions = [ """ SyslogAlertForwarder: """ ]
  Fields = [
    """SyslogAlertForwarder:\s*(|({host}[^;]+?))\s*;\s*(?:N\/A||({domain}[^;]+?))\s*;([^;]*;){2}\s*(?:N\/A||({protocol}[^;]+?))\s*;([^;]*;){3}\s*(?:N\/A||({alert_name}(({alert_type}[^;:]+?):)?\s*[^;]+?))\s*;\s*(?:N\/A||({alert_severity}[^;]+?))\s*;[^;]*;\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d \w+);[^;]*;\s*(?:N\/A||({category}[^;]+?))\s*;([^;]*;){2}\s*(?:N\/A||({dest_ip}[a-fA-F\d.:]+))\s*;[^;]*;\s*(?:N\/A||({dest_port}\d+?))\s*;([^;]*;){6}\s*(?:N\/A||({direction}[^;]+?))\s*;\s*(?:N\/A||({interface}[^;]+?))\s*;""",
    """;\s*(?:N\/A|({md5}\w+)|[^;]*?)\s*;([^;]*;){6}\s*(?:N\/A|n\/a|({result_status}[^;]+?))\s*;[^;]*;\s*(?:N\/A||({src_ip}[a-fA-F\d.:]+)|[^;]*)\s*;\s*(?:N\/A||({src_port}\d+)|[^;]*)\s*;\s*(?:N\/A||({sub_category}[^;]+?))\s*(;[^;]*){6}\s*$""",
  ]
}
```