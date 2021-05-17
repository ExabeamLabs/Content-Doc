#### Parser Content
```Java
{
Name = s-endpoint-dlp-alert
    Vendor = EndPoint
  Product = EndPoint
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "yyyy/MM/dd H:mm:ss"
    Conditions = [ """ [endpoint_user_name="""", """ [policy_rule="""" ]
    Fields = [
      """\w+ \d\d \d\d:\d\d:\d\d ({host}[\w.\-]{1,2000}) \S+ \[""",
      """\s\[computer="({src_host}[^"]{1,2000})""",
      """\s\[url="(N\/A|({malware_url}[^"]{1,2000}))""",
      """\s\[app_name="({process_name}[^"]{1,2000})""",
      """\s\[id="({alert_id}[^"]{1,2000})""",
      """\s\[endpoint_user_name="(({domain}[^"]{1,2000})[\\\/]{1,2000})?({user}[^"\\\/]{1,2000})""",
      """\s\[ip_addr="({src_ip}[^"]{1,2000})""",
      """\s\[protocol_device_taisyou="({alert_type}[^"]{1,2000})""",
      """\s\[policy_rule="({alert_name}[^"]{1,2000})""",
      """\s\[syadan="({action}[^"]{1,2000})""",
      """\s\[jyudaido="({alert_severity}[^"]{1,2000})""",
      """\s\[soushinsya="(N\/A|({src_ip}[^"]{1,2000}))""",
      """\s\[taisyou_ip="(N\/A|({dest_ip}[^"]{1,2000}))""",
      """\s\[tenpu_file_name="[^"]{0,2000}?({malware_file_name}[^"\\\/]{1,2000}?)\s{0,100}"""",
      """\s\[hasseibi="({time}\d\d\d\d\/\d\d\/\d\d \d{1,100}:\d{1,100}:\d{1,100})""",
    ]
  }
```