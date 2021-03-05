#### Parser Content
```Java
{
Name = s-carbonblack-process-alert
  Vendor = Carbon Black
  Product = Cb Protection
  Lms = Splunk
  DataType = "process-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"legacy_alert_id"""", """"threat_indicators"""", """"reason_code"""", """_threat_category"""" ]
  Fields = [
    """carbonblack,"({host}[^"]+)"""",
    """"+create_time"+:"+({time}[^"]+)"+""",
    """"+severity":({alert_severity}[^,]+),""",
    """"+category"+:"+({category}[^"]+)"+""",
    """"+threat_id"+:"+({threat_id}[^"]+)"+""",
    """"+device_username"+:"+(\w+\\+)?({user}[^"]+)"+""",
    """"+device_name"+:"+(\w+\\+)?({src_host}[^."]+)""",
    """"+reason_code"+:"+({alert_name}.*?)"+,"+\w+"+:""",
    """"+threat_indicators":.*?"process_name"+:"+({process_name}[^"]+)"+""",
    """"+reason"+:"+({additional_info}[^"]+)"+""",
    """"+threat_indicators":.*?"sha256"+:"+({sha256}[^"]+)"+""",
    """"+threat_indicators"+:.*?"+ttps"+:\["+({process}.*?)"+\]""",
    """"+device_os"+:"+({os}[^"]+)"+""",
    """"+device_os_version"+:"+({os_revision}[^"]+)"+""",
    """"+policy_name"+:"+({policy}[^"]+)"+""",
    """"+state"+:"+({state}[^"]+)"+""",
    """"+type"+:"+({alert_type}[^"]+)"+""",
    """"+legacy_alert_id"+:"+({alert_id}[^"]+)"+""",
    """"+id"+:"+({sensor_id}.*?)"+""",
    """"+org_key"+:"+({primary_key}[^"]+)"+""",
    """"+not_blocked_threat_category"+:"+(UNKNOWN|({outcome}.*?))"+""",
    """"+blocked_threat_category"+:"+(UNKNOWN|({outcome}.*?))"+""",
    """"+id"+:"+({pid}.*?)"+,"+legacy_alert_id""",
    """"+changed_by"+:"+({process_vendor}.*?)"+""",
    """"+ioc_id"+:"+({ioc}.*?)"+""",
  ]
}
```