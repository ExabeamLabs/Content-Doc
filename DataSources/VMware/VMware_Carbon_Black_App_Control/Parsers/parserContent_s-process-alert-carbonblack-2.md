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
    """exabeam_host=({host}[^\s]+)""",
    """host='({host}[^']+)""",
    """timestamp='({time}\d+)""",
    """interface_ip='(0.0.0.0|({dest_ip}[A-Fa-f\d:.]+))'""",
    """reason=({alert_type}[^\s]+)""",
    """watchlist_name='({alert_name}[^']+)'""",
    """process_md5='({md5}[^']+)""",
    """process_guid=({process_guid}[^\s]+)""",
    """sensor_id=({sensor_id}[^\s]+)""",
    """process_path='({process}({process_directory}(?:[^=]+)?[\\\/])?({process_name}[^\\\/=]+))'\s+\w+=""",
    """process_name='({process_name}[^']+)'""",
  ]
}
```