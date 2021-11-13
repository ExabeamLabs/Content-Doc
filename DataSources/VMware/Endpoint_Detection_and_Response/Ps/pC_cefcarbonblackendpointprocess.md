#### Parser Content
```Java
{
Name = cef-carbonblack-endpoint-process
  Vendor = VMware
  Product = Endpoint Detection and Response 
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  DataType = "process-created"
  Conditions = [ """CEF:""", """event_type_cd""" , """|SkyFormation Cloud Apps Security""", """sensor_product_cd":"cb_response"""", """requestClientApplication=RedCanary""", """destinationServiceName =Custom Application""", """process_path""" ]
  Fields =[
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z).*?Skyformation""",
    """"sensor_id"{1,20}:"{1,20}({sensor_id}[^"]{1,2000})""",
    """"{1,20}process_path"{1,20}:"{1,20}({process}({directory}[^"]{1,2000}(\\|\/)+)?({process_name}[^"]{1,2000}))""",
    """"host_name"{1,20}:"{1,20}({host}[^"]{1,2000})""",
    """"process_command_line"{1,20}:"{1,20}({command_line}[^"]{1,2000})"{0,20

}
```