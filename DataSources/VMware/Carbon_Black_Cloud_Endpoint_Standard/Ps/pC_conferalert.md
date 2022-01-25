#### Parser Content
```Java
{
Name = confer-alert
  Vendor = VMware
  Product = Carbon Black Cloud Endpoint Standard
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """"threatInfo"""",""""indicators"""",""""summary"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """eventTime"{1,20}:\s{0,100}({time}\d{1,100})""",
    """email"{1,20}:\s{0,100}"{1,20}(({user_email}[^@"]{1,2000}@[^"]{1,2000})|((({domain}[^\\"]{1,2000})\\+)?({user}[^"]{1,2000})))"""",
    """deviceName"{1,20}:\s{0,100}"{1,20}([^\\"]{1,2000}\\+)?({src_host}[^"]{1,2000})"""",
    """ruleName"{1,20}:\s{0,100}"{1,20}(Confer - )?({alert_name}[^"]{1,2000})"""",
    """type"{1,20}:\s{0,100}"{1,20}({alert_type}[^"]{1,2000})"""",
    """incidentId"{1,20}:\s{0,100}"{1,20}({alert_id}[^"]{1,2000})"""",
    """score"{1,20}:\s{0,100}({alert_severity}\d{1,100})""",
    """summary"{1,20}:\s{0,100}"{1,20}({additional_info}[^"]{1,2000})"""",
    """eventDescription"{1,20}:\s{0,100}"{1,20}({additional_info}[^"]{1,2000})"""",
    """deviceType"{1,20}:\s{0,100}"{1,20}({os}[^"]{1,2000})"""",
    """externalIpAddress"{1,20}:\s{0,100}"{1,20}({dest_ip}[^"]{1,2000})"""",
    """applicationName":\s"({process_name}[^"]{1,2000})""",
  ]


}
```