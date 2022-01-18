#### Parser Content
```Java
{
Name = s-process-alert-carbonblack-2
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = Splunk
  DataType = "process-alert"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """reason=watchlist.hit""", """watchlist_name='""", """watchlist_id=""", """process_guid=""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """host='({host}[^']{1,2000})""",
    """timestamp='({time}\d{1,100})""",
    """interface_ip='(0.0.0.0|({dest_ip}[A-Fa-f\d:.]{1,2000}))'""",
    """reason=({alert_type}[^\s]{1,2000})""",
    """watchlist_name='({alert_name}[^']{1,2000})'""",
    """process_md5='({md5}[^']{1,2000})""",
    """process_guid=({process_guid}[^\s]{1,2000})""",
    """sensor_id=({sensor_id}[^\s]{1,2000})""",
    """process_path='({process}({process_directory}(?:[^=]{1,2000})?[\\\/])?({process_name}[^\\\/=]{1,2000}))'\s{1,100}\w+=""",
    """process_name='({process_name}[^']{1,2000})'""",
  ]


}
```