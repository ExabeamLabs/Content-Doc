#### Parser Content
```Java
{
Name = cef-mbmc-security-alert-detection-1
    Conditions = [ """CEF:""", """|Malwarebytes|Malwarebytes""", """|Detection|""" ]
    Fields = ${MBMCParserTemplates.cef-malwarebytes-security-alert.Fields} [
      """msg=({additional_info}.+?)\s*\w+=""",
      """filePath=.*?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({dest_port}\d+))?)"""
    ]
    DupFields = ["src_host->host"]
  }
```