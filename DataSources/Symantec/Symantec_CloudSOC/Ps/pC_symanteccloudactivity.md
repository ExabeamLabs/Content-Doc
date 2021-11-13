#### Parser Content
```Java
{
Name = symantec-cloud-activity
  Vendor = Symantec
  Product = Symantec CloudSOC
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""SkyFormation Cloud Apps Security""" , """destinationServiceName =Symantec CloudSOC""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """ext__inserted_timestamp_=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
    """suser=({user_email}[^\s]{1,2000}@({email_domain}.+?))\s\w+=""",
    """ext__user_name_=({user_fullname}[^\s@]{1,2000}\s{1,100}[^=]{1,2000})\s\w+=""",
    """ext_user=({user_email}[^\s]{1,2000}@({email_domain}.+?))\s\w+="""
    """ext_user=(system|({user}[^\s\@]{1,2000}))\s\w+=""",
    """ext_service=({app}.+?)\s\w+=""",
    """ext__user_agent_=({user_agent}.+?)\s\w+=""",
    """ext__object_name_=(|({file_path}({file_parent}[^=]{0,2000}?[\\\/]{1,2000})?(|({file_name}[^\\\/=]{0,2000}?(\.({file_ext}\w*))?)?)))\s{1,100}\w+=""",
    """flexString1=({activity}.+?)\s\w+=""",
    """ext_message=({additional_info}.+?)\s\w+=""",
    """fname=({object}.+?)\s\w+=""",
    """ext_severity=({alert_severity}.+?)\s\w+=""",
    """src=({src_ip}[^\s]{1,2000})""",
    """ext__shared_with_=({target}[^\s]{1,2000})\s\w+="""
  ]
  DupFields = ["file_path->resource", "app->service", "activity->accesses"]


}
```