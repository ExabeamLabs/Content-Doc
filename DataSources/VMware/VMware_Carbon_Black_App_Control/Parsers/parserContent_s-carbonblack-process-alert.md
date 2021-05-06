#### Parser Content
```Java
{
Name = s-carbonblack-process-alert
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = Splunk
  DataType = "process-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"legacy_alert_id"""", """"threat_indicators"""", """"reason_code"""", """_threat_category"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """carbonblack,"({host}[^"]+?)"""",
    """"+create_time"+:\s*"+({time}[^"]+?)"+""",
    """"+severity":\s*({alert_severity}[^,]+?),""",
    """"+category"+:\s*"+({category}[^"]+?)"+""",
    """"+threat_id"+:\s*"+({threat_id}[^"]+?)"+""",
    """"+device_username"+:\s*"+(({user_email}[^@,"]+@[^",]+)|(({domain}[^\\"]+?)\\+)?({user}[^"]+))"+""",
    """"+device_name"+:\s*"+(\w+\\+)?({host}[^."]+)""",
    """"+reason_code"+:\s*"+({alert_name}[^,]+?)",""",
    """"+threat_indicators":[^\}\]]*?"process_name"+:\s*"+({process_name}[^"]+?)"+""",
    """"+reason"+:\s*"+({additional_info}[^"]+?)"+""",
    """"+threat_indicators":[^\}\]]*?"sha256"+:\s*"+({sha256}[^"]+?)"+""",
    """"+threat_indicators"+:[^\}\]]*?"+ttps"+:\s*\["+({process}[^"]+?)"+\]""",
    """"+device_os"+:\s*"+({os}[^"]+?)"+""",
    """"+device_os_version"+:\s*"+({os_revision}[^"]+?)"+""",
    """"+policy_name"+:\s*"+({policy}[^"]+?)"+""",
    """"+state"+:\s*"+({state}[^"]+?)"+""",
    """"+type"+:\s*"+({alert_type}[^"]+?)"+""",
    """"+legacy_alert_id"+:\s*"+({alert_id}[^"]+?)"+""",
    """"+id"+:\s*"+({sensor_id}[^"]+?)"+""",
    """"+org_key"+:\s*"+({primary_key}[^"]+?)"+""",
    """"+not_blocked_threat_category"+:\s*"+(UNKNOWN|({outcome}[^"]+?))"+""",
    """"+blocked_threat_category"+:\s*"+(UNKNOWN|({outcome}[^"]+?))"+""",
    """"+id"+:\s*"+({pid}[^"]+?)"+,"+legacy_alert_id""",
    """"+changed_by"+:\s*"+({process_vendor}[^"]+?)"+""",
    """"+ioc_id"+:\s*"+({ioc}[^"]+?)"+""",
    """"+report_name"+:\s*"+({alert_name}[^,]+?)",""",
    """"+report_id"+:\s*"+({alert_id}[^"]+?)"+""",
    """"process_name"+:"+({process_name}[^"]+)""",
    """"threat_cause_actor_name"+:"+({process}({process_directory}[^"]+)\\({process_name}[^"]+))"""",
    """"threat_cause_actor_process_pid"+:"+({pid}[^"]+)""",
    """device_internal_ip"+:"+({src_ip}[A-Fa-f.:\d]+)"""
  ]
}
```