#### Parser Content
```Java
{
Name = cef-carbonblack-process-alert-storage
  DataType = "process-alert"
  IsHVF = true
  Conditions = [ """reason=feed.storage.""", """host=""" , """feed_id=""", """feed_name=""" ]

cef-carbonblack-process-alert-1 = {
  Vendor = VMware
  Product = Endpoint Detection and Response 
  Lms = Direct
  DataType = "process-alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:SS"
  Fields = [
  """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
  """reason=({alert_type}[^\s]{1,2000})""",
  """feed_name='({alert_name}[^']{1,2000})""",
  """alliance_score_.+?='({alert_severity}[-\d]{1,2000})""",
  """host='({host}[^']{1,2000})""",
  """interface_ip='(0.0.0.0|({dest_ip}[A-Fa-f\d:.]{1,2000}))'""", 
  """process_md5='({md5}[^']{1,2000})""",
  """process_guid=({process_guid}[^\s]{1,2000})""",
  """sensor_id=({sensor_id}[^\s]{1,2000})""",
  """process_path='({process}({process_directory}(?:[^=]{1,2000})?[\\\/])?({process_name}[^\\\/=]{1,2000}))'\s{1,100}\w+=""",
  """process_name='({process_name}[^']{1,2000})'""",
  """ioc_value='({additional_info}[^']{1,2000})'""",
  """feed_id=({alert_id}\d{1,100})""", 
  ]
  DupFields = ["host->dest_host"
}
```