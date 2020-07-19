#### Parser Content
```Java
{
Name = cef-carbonblack-endpoint-process
  Vendor = Carbon Black
  Product = Cb Response
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  DataType = "process-created"
  Conditions = [ """CEF:""", """event_type_cd""" , """|SkyFormation Cloud Apps Security""", """sensor_product_cd":"cb_response"""", """requestClientApplication=RedCanary""", """destinationServiceName=Custom Application""", """process_path""" ]
  Fields =[
    """({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z).*?Skyformation""",
    """"sensor_id"+:"+({sensor_id}[^"]+)""",
    """"+process_path"+:"+({process}({directory}[^"]+(\\|\/)+)?({process_name}[^"]+))""",
    """"host_name"+:"+({host}[^"]+)""",
    """"process_command_line"+:"+({command_line}[^"]+)"*,""",
    """"process_md5"+:"+({md5}[^"]+)"*,""",
    """"user_username"+:"+({user}[^"]+)"*,""",
    """"user_domain"+:"+({domain}[^"]+)"*,"""
    ]
    DupFields = ["host->dest_host"]
}

${CarbonBlackParserTemplates.cef-carbonblack-process-alert-1}{
  Name = cef-carbonblack-process-alert-storage
  DataType = "process-alert"
  IsHVF = true
  Conditions = [ """reason=feed.storage.""", """host=""" , """feed_id=""", """feed_name=""" ]
}
```