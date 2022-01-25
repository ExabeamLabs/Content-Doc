#### Parser Content
```Java
{
Name = lumension-failed-usb-activity-1
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ READ-DENIED """, """ DeviceType="""", """ DeviceName="""" ]
  Fields = ${LumensionParserTemplates.lumension-usb-activity.Fields} [
    """scomc\s{1,100}(System|({process_name}.+?)) READ-DENIED \[""",
  ]
}
lumension-usb-activity = {
  Vendor = Lumension
  Product = Lumension
  Lms = Direct
  DataType = "usb-activity"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d(:|-)\d\d(:|-)\d\dZ) (|({host}[\w\-.]{1,2000})) scomc.+?({activity}\S+) \[""",
    """User="({user_sid}[^"]{1,2000})""",
    """UserName="((NT AUTHORITY|({domain}[^"\\]{1,2000}))\\+)?(SYSTEM|({user}[^\\\s"]{1,2000}))""",
    """DeviceType="(Unknown|({device_type}[^"]{1,2000}))""",
    """DeviceName="({device_id}[^"]{1,2000})""",
    """Filename="({file_path}[^"]{1,2000})""",
    """Filename="[^"]{0,2000}\\+({file_name}[^\\"]{1,2000}?(\.({file_ext}[^\.\s"]{1,2000}))?)"""",
    """Reason="({activity_details}[^"]{1,2000})""",
    """({bytes}\d{1,100}) bytes""",
  ]

```