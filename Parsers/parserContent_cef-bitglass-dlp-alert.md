#### Parser Content
```Java
{
Name = cef-bitglass-dlp-alert
  Vendor = Bitglass
  Product = Bitglass CASB
  Lms = ArcSight
  DataType = "dlp-alert"
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """CEF:""", """|Skyformation|""", """"action":"Alert"""" ]
  Fields = [
    """ext_time=({time}\d+\s+\w+\s+\d+\s+\d+:\d+:\d+)""",
    """ext_patterns=({alert_name}.+?)\s+(\w+=|$)""",
    """ext_status=({alert_type}.+?)\s+(\w+=|$)""",
    """ext_folder=({target}.+?)\s+(\w+=|$)""",
    """ext_filename=\s*(|({file_name}.+?(\.({file_ext}[^\.\s"]+))?))\s+(\w+=|$)""",
    """ext_application=({process}.+?)\s+(\w+=|$)""",
    """ext_owner=({user_email}.+?)\s+(\w+=|$)""",
    """ext_filelink=({additional_info}.+?)\s+(\w+=|$)""",
  ]
}
```