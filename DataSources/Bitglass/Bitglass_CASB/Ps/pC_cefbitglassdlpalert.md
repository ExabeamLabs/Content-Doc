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
    """ext_time=({time}\d{1,100}\s{1,100}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})""",
    """ext_patterns=({alert_name}.+?)\s{1,100}(\w+=|$)""",
    """ext_status=({alert_type}.+?)\s{1,100}(\w+=|$)""",
    """ext_folder=({target}.+?)\s{1,100}(\w+=|$)""",
    """ext_filename=\s{0,100}(|({file_name}.+?(\.({file_ext}[^\.\s"]{1,2000}))?))\s{1,100}(\w+=|$)""",
    """ext_application=({process}.+?)\s{1,100}(\w+=|$)""",
    """ext_owner=({user_email}.+?)\s{1,100}(\w+=|$)""",
    """ext_filelink=({additional_info}.+?)\s{1,100}(\w+=|$)""",
  ]


}
```