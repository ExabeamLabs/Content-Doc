#### Parser Content
```Java
{
Name = lumension-failed-usb-activity-2
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ WRITE-DENIED """, """ DeviceType="""", """ DeviceName="""" ]
  Fields = ${LumensionParserTemplates.lumension-usb-activity.Fields} [
    """scomc\s{1,100}(System|({process_name}.+?)) WRITE-DENIED \[""",
  ]
}
lumension-usb-activity = {
  Vendor = Lumension
  Product = Lumension
  Lms = Direct
  DataType = "usb-activity"
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d(:|-)\d\d(:|-)\d\dZ) (|({host}[\w\-.]+)) scomc.+?({activity}\S+) \[""",
    """User="({user_sid}[^"]+)""",
    """UserName="((NT AUTHORITY|({domain}[^"\\]+))\\+)?(SYSTEM|({user}[^\\\s"]+))""",
    """DeviceType="(Unknown|({device_type}[^"]+))""",
    """DeviceName="({device_id}[^"]+)""",
    """Filename="({file_path}[^"]+)""",
    """Filename="[^"]*\\+({file_name}[^\\"]+?(\.({file_ext}[^\.\s"]+))?)"""",
    """Reason="({activity_details}[^"]+)""",
    """({bytes}\d{1,100}) bytes""",
  ]

```