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
    """exabeam_host=([^=@]+@\s*)?({host}\S+)""",
    """"serial_event_id":\s*({alert_id}\d+)""",
    """"pid":\s*({pid}\d+)""",
    """"sha256":\s*"({sha256_sum}[^",]+)""",
    """"process_name":\s*"({process_name}[^",]+)""",
    """"user_name":\s*"(SYSTEM|({user}[^",]+))""",
    """"timestamp_utc":\s*"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"parent_process_path":\s*"({parent_process_path}[^",]+)""",
    """"original_file_name":\s*"({file_name}[^",]+)""",
    """"user_sid":\s*"({user_sid}[^",]+)""",
    """"parent_process_name":\s*"({parent_process}[^",]+)""",
    """"process_path":\s*"({process}({process_directory}.*?)(\\+({process_name}[^\\"]+?))?)"""",
    """"user_domain":\s*"({domain}[^",]+)""",
    """"md5":\s*"({md5_sum}[^",]+)""",
    """"opcode":\s*({opcode}\d+)""",
    """"command_line":\s*"({command_line}.+?)"(,|\})""",
    """"rule_id":\s*"({rule_id}[^"]+)""",
    """"event_type_human":\s*"({event_name}[^"]+)""",
    """"rule_name":\s*"({alert_name}[^"]+)""",
    """severity":\s*"({alert_severity}[^"]+)""",
    """"hostname":\s*"({src_host}[^"]+)""",
    """"ip_address":\s*"({src_ip}[^"]+)""",
    """"operating_system":\s*"({os}[^"]+)""",
  ]
}
```