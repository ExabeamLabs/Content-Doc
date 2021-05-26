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
    """"severity":"({alert_severity}[^"]{1,2000})"""",
    """"incident_type":"({alert_type}[^"]{1,2000})"""",
    """"computer_ip":"({host}[^"]{1,2000})"""",
    """"computer_name":"({host}[^"]{1,2000})"""",
    """"device_friendly_name_":"({device_id}[^"]{1,2000})"""",
    """"actual_action":"({outcome}[^"]{1,2000})"""",
    """"total_content_size_kb":"({bytes_num}[^"]{1,2000})"""",
    """total_content_size_({bytes_unit}[^"]{1,2000})":"\d""",
    """"user_name":"({user}[^"]{1,2000})"""",
    """"user_groups":"({additional_info}[^"]{1,2000})"""",
    """"incident_id":"({alert_id}[^"]{1,2000})"""",
    """"destination":"({target}[^"]{1,2000})"""",
    """"rules":"({alert_name}[^",]{1,2000})(,|")""",
    """"source_application_file_name":"(?:None|({process}[^"]{1,2000}))""",
    """"evidence_file_path":"(?:None|\w+:\\+([^\\"]{1,2000}\\+)+({file_name}[^"]{1,2000}))"""",
    """"evidence_file_path":"(?:None|({file_path}[^"]{1,2000}))"""",
  ]
}
```