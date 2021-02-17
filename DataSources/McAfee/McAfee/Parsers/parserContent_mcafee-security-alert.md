#### Parser Content
```Java
{
Name = mcafee-security-alert
  Vendor = McAfee
  Lms = Direct
  DataType = "alert"
  TimeFormat = "dd/MM/yy HH:mm:ss"
  Conditions = [ """<custom_condition_cont-6876> """ ]
  Fields = [
    """\d\d/\d\d/\d\d \d\d:\d\d:\d\d,({time}\d\d/\d\d/\d\d \d\d:\d\d:\d\d),(|({host}[^,]+)),(|N/A|"({user}[^",]+?),[^"]*"|({=user}[^,]+)),(|({src_ip}[a-fA-F\d.:]+)),(|({src_mac}[^,]+)),(|({dest_host}[^,]+)),(|((?i)none)|_|({alert_name}[^,]+)),(|((?i)none)|({action}[^,]+)),[^,]*,(|({alert_severity}[^,]+)),(|_|({src_host}[^,]+)),(|({=src_ip}[a-fA-F\d.:]+)),(|({malware_url}[^,]+)),\s*(|((?i)none)|({alert_type}[^,]+?))\s*,(|({additional_info}[^,]+)),(|({malware_file_name}[^,]+)),""",
  ]
}
```