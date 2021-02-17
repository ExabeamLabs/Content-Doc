#### Parser Content
```Java
{
Name = s-endpoint-dlp-alert
    Vendor = EndPoint
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "yyyy/MM/dd H:mm:ss"
    Conditions = [ """ [endpoint_user_name="""", """ [policy_rule="""" ]
    Fields = [
      """\w+ \d\d \d\d:\d\d:\d\d ({host}[\w.\-]+) \S+ \[""",
      """\s\[computer="({src_host}[^"]+)""",
      """\s\[url="(N\/A|({malware_url}[^"]+))""",
      """\s\[app_name="({process_name}[^"]+)""",
      """\s\[id="({alert_id}[^"]+)""",
      """\s\[endpoint_user_name="(({domain}[^"]+)[\\\/]+)?({user}[^"\\\/]+)""",
      """\s\[ip_addr="({src_ip}[^"]+)""",
      """\s\[protocol_device_taisyou="({alert_type}[^"]+)""",
      """\s\[policy_rule="({alert_name}[^"]+)""",
      """\s\[syadan="({action}[^"]+)""",
      """\s\[jyudaido="({alert_severity}[^"]+)""",
      """\s\[soushinsya="(N\/A|({src_ip}[^"]+))""",
      """\s\[taisyou_ip="(N\/A|({dest_ip}[^"]+))""",
      """\s\[tenpu_file_name="[^"]*?({malware_file_name}[^"\\\/]+?)\s*"""",
      """\s\[hasseibi="({time}\d\d\d\d\/\d\d\/\d\d \d+:\d+:\d+)""",
    ]
  }
```