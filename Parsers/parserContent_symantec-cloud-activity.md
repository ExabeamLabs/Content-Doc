#### Parser Content
```Java
{
Name = symantec-cloud-activity
  Vendor = Symantec
  Product = Symantec CloudSOC
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""SkyFormation Cloud Apps Security""" , """destinationServiceName=Symantec CloudSOC""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """\s({host}[\w\-.]+)\s+Skyformation""",
    """ext__inserted_timestamp_=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
    """suser=({user_email}[^\s]+@.+?)\s\w+=""",
    """ext__user_name_=({user_fullname}[^\s@]+\s+[^=]+)\s\w+=""",
    """ext_user=({user_email}[^\s]+@.+?)\s\w+="""
    """ext_user=(system|({user}[^\s\@]+))\s\w+=""",
    """ext_service=({app}.+?)\s\w+=""",
    """ext_browser=(Unknown|({browser}.+?))\s\w+=""",
    """ext__user_agent_=({user_agent}.+?)\s\w+=""",
    """ext__object_name_=(|({file_path}({file_parent}[^=]*?[\\\/]+)?(|({file_name}[^\\\/=]*?(\.({file_ext}\w*))?)?)))\s+\w+=""",
    """flexString1=({activity}.+?)\s\w+=""",
    """ext_message=({additional_info}.+?)\s\w+=""",
    """fname=({object}.+?)\s\w+=""",
    """ext_severity=({alert_severity}.+?)\s\w+=""",
    """src=({src_ip}[^\s]+)""",
    """ext__shared_with_=({target}[^\s]+)\s\w+="""
  ]
  DupFields = ["file_path->resource", "app->service", "activity->accesses"]
}

{
  Name = s-symantec-email-alert
  Vendor = Symantec
  Product = Symantec Email Security.cloud
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """"mailProcessingStartTime": """, """"isOutbound": """, """"envFrom": """, """"senderIp": """ ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"mailProcessingStartTime":\s*({time}\d+)""",
    """"isOutbound":\s*({is_outbound}[^,]+)""",
    """"envFrom":\s*"({sender}[^"@]+@({external_domain_sender}[^"@]+))""",
    """"envTo":\s*\[({recipients}"({recipient}[^"@]+@({external_domain_recipient}[^"@]+))".*?)\]""",
    """"subject":\s*"\s*({subject}.+?)\s*"""",
    """"senderIp":\s*"*({src_ip}[a-fA-F\d.:]+)""",
    """"fileNameOrURL":\s*"({attachment}[^"]+)""",
    """"severity":\s*"({alert_severity}[^"]+)""",
    """"securityService":\s*"({alert_type}[^"]+)"""",
    """"action":\s*"({outcome}[^"]+)""",
    """"malwareName":\s*"(null|unknown|({alert_name}[^"]+))""",
    """"malwareCategory":\s*"({threat_category}[^"]+)""",
  ]
}
```