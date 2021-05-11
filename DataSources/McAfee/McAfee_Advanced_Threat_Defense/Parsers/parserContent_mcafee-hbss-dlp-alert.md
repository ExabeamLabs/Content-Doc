#### Parser Content
```Java
{
Name = mcafee-hbss-dlp-alert
  Vendor = McAfee
  Product = McAfee Advanced Threat Defense
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "MMM dd, YYYY HH:mm:ss a"
  Conditions = ["""occurred_endpoint""" , """device_class_name""" , """DLP for Windows"""]
  Fields = [
    """"occurred_endpoint":"({time}\w+\s\d\d,\s\d\d\d\d\s\d{1,100}:\d\d:\d\d\s(am|AM|pm|PM))""",
    """"severity":"({alert_severity}[^"]+)"""",
    """"incident_type":"({alert_type}[^"]+)"""",
    """"computer_ip":"({host}[^"]+)"""",
    """"computer_name":"({host}[^"]+)"""",
    """"device_friendly_name_":"({device_id}[^"]+)"""",
    """"actual_action":"({outcome}[^"]+)"""",
    """"total_content_size_kb":"({bytes_num}[^"]+)"""",
    """total_content_size_({bytes_unit}[^"]+)":"\d""",
    """"user_name":"({user}[^"]+)"""",
    """"user_groups":"({additional_info}[^"]+)"""",
    """"incident_id":"({alert_id}[^"]+)"""",
    """"destination":"({target}[^"]+)"""",
    """"rules":"({alert_name}[^",]+)(,|")""",
    """"source_application_file_name":"(?:None|({process}[^"]+))""",
    """"evidence_file_path":"(?:None|\w+:\\+([^\\"]+\\+)+({file_name}[^"]+))"""",
    """"evidence_file_path":"(?:None|({file_path}[^"]+))"""",
  ]
}
```