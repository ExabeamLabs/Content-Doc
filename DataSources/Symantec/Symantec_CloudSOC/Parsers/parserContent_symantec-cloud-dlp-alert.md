#### Parser Content
```Java
{
Name = symantec-cloud-dlp-alert
  Vendor = Symantec
  Product = Symantec CloudSOC
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""Security Alert Detected by""" , """SkyFormation Cloud Apps Security""" , """destinationServiceName=Symantec CloudSOC""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """\s({host}[\w\-.]+)\s+Skyformation""",
    """ext__inserted_timestamp_=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
    """suser=({user_email}[^\s]+@.+?)\s\w+=""",
    """ext__user_name_=({user_fullname}[^\s@]+\s+[^=]+)\s\w+=""",
    """ext_user=({user_email}[^\s]+@.+?)\s\w+="""
    """ext_user=({user}[^\s\@]+)\s\w+=""",
    """ext_service=({process}.+?)\s\w+=""",
    """ext_browser=({browser}.+?)\s\w+=""",
    """ext__user_agent_=({user_agent}.+?)\s\w+=""",
    """ext__object_name_=({file_path}({file_parent}.*\/)({file_name}[^\s]+))\s\w+=""",
    """ext__activity_type_=({alert_type}.+?)\s\w+=""",
    """ext_message=({alert_name}.+?)\s\w+=""",
    """fname=({file_name}.+?)\s\w+=""",
    """flexString1=({activity}.+?)\s\w+=""",
    """ext_severity=({alert_severity}.+?)\s\w+=""",
    """src=({src_ip}[^\s]+)""",
  ]
  DupFields = ["file_path->resource"]
}
```