#### Parser Content
```Java
{
Name = endgame-edr-security-alert
  Vendor = Endgame
  Product = Endgame EDR
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """investigation_id""", """doc_type": "alert""", """origination_task_id"""  ]
  Fields = [
    """exabeam_host=([^=@]{1,2000}@\s{0,100})?({host}\S+)""",
    """"serial_event_id":\s{0,100}({alert_id}\d{1,100})""",
    """"pid":\s{0,100}({pid}\d{1,100})""",
    """"sha256":\s{0,100}"({sha256_sum}[^",]{1,2000})""",
    """"process_name":\s{0,100}"({process_name}[^",]{1,2000})""",
    """"user_name":\s{0,100}"(SYSTEM|({user}[^",]{1,2000}))""",
    """"timestamp_utc":\s{0,100}"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"parent_process_path":\s{0,100}"({parent_process_path}[^",]{1,2000})""",
    """"original_file_name":\s{0,100}"({file_name}[^",]{1,2000})""",
    """"user_sid":\s{0,100}"({user_sid}[^",]{1,2000})""",
    """"parent_process_name":\s{0,100}"({parent_process}[^",]{1,2000})""",
    """"process_path":\s{0,100}"({process}({process_directory}.*?)(\\+({process_name}[^\\"]{1,2000}?))?)"""",
    """"user_domain":\s{0,100}"({domain}[^",]{1,2000})""",
    """"md5":\s{0,100}"({md5_sum}[^",]{1,2000})""",
    """"opcode":\s{0,100}({opcode}\d{1,100})""",
    """"command_line":\s{0,100}"({command_line}.+?)"(,|\})""",
    """"rule_id":\s{0,100}"({rule_id}[^"]{1,2000})""",
    """"event_type_human":\s{0,100}"({event_name}[^"]{1,2000})""",
    """"rule_name":\s{0,100}"({alert_name}[^"]{1,2000})""",
    """severity":\s{0,100}"({alert_severity}[^"]{1,2000})""",
    """"hostname":\s{0,100}"({src_host}[^"]{1,2000})""",
    """"ip_address":\s{0,100}"({src_ip}[^"]{1,2000})""",
    """"operating_system":\s{0,100}"({os}[^"]{1,2000})""",
  ]
}
```