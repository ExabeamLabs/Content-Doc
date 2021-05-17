#### Parser Content
```Java
{
Name = s-pharos-print-activity
  Vendor = Pharos
  Product = Pharos
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """ JobName=""", """ UserName=""", """ DeviceName=""", """ Time_Printed=""",]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """(^|exabeam_\w+=)({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100})\s{1,100}(?!exabeam)""",
    """\sUserName=({user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sJobName="?({object}.+?)"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sPages=({num_pages}\d{1,100})(\s{1,100}\w+=|\s{0,100}$)""",
    """\sFileSize=({bytes}\d{1,100})(\s{1,100}\w+=|\s{0,100}$)""",
    """\sDeviceName=({printer_name}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sDeviceName=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s{1,100}\w+=|\s{0,100}$)""",
    """\sApplicationName=(Unknown|({process_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```