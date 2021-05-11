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
    """exabeam_host=([^=@]+@\s{0,100})?({host}\S+)""",
    """"serial_event_id":\s{0,100}({alert_id}\d{1,100})""",
    """"pid":\s{0,100}({pid}\d{1,100})""",
    """"sha256":\s{0,100}"({sha256_sum}[^",]+)""",
    """"process_name":\s{0,100}"({process_name}[^",]+)""",
    """"user_name":\s{0,100}"(SYSTEM|({user}[^",]+))""",
    """"timestamp_utc":\s{0,100}"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"parent_process_path":\s{0,100}"({parent_process_path}[^",]+)""",
    """"original_file_name":\s{0,100}"({file_name}[^",]+)""",
    """"user_sid":\s{0,100}"({user_sid}[^",]+)""",
    """"parent_process_name":\s{0,100}"({parent_process}[^",]+)""",
    """"process_path":\s{0,100}"({process}({process_directory}.*?)(\\+({process_name}[^\\"]+?))?)"""",
    """"user_domain":\s{0,100}"({domain}[^",]+)""",
    """"md5":\s{0,100}"({md5_sum}[^",]+)""",
    """"opcode":\s{0,100}({opcode}\d{1,100})""",
    """"command_line":\s{0,100}"({command_line}.+?)"(,|\})""",
    """"rule_id":\s{0,100}"({rule_id}[^"]+)""",
    """"event_type_human":\s{0,100}"({event_name}[^"]+)""",
    """"rule_name":\s{0,100}"({alert_name}[^"]+)""",
    """severity":\s{0,100}"({alert_severity}[^"]+)""",
    """"hostname":\s{0,100}"({src_host}[^"]+)""",
    """"ip_address":\s{0,100}"({src_ip}[^"]+)""",
    """"operating_system":\s{0,100}"({os}[^"]+)""",
  ]
}
```